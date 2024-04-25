import datetime
from math import ceil
from fastapi import APIRouter, Depends, Form, HTTPException, Request, BackgroundTasks
from pydantic import EmailStr
from core.db import get_session, handle_db_transaction
from apps.device.models import DeviceRequestRecord, User
from auth import auth
from auth.permissions import PermissionChecker
from core import constants
from core.email import send_mail
from core.utils import (
    response_model,
    generate_password,
    log_request,
)

from core.pydantic import DeleteModel

from apps.user.schemas import (
    ChangePasswordModel,
    LoginModel,
    RefreshTokenModel,
    ResetPasswordModel,
    UserAddModel,
    UserUpdateModel,
)

router = APIRouter()


@router.post("/password/forget", tags=["Authentication"])
async def forget_password(
    resetPassword: ResetPasswordModel, backgroundTasks: BackgroundTasks
):
    session = next(get_session())
    user_object = User.from_email(resetPassword.email)
    password = generate_password(12)
    backgroundTasks.add_task(
        send_mail.reset_mail,
        email_to_send_to=resetPassword.email,
        username=user_object.full_name,
        password=password,
    )
    user_object.temp_password = auth.hash_password(password)
    user_object.temp_password_created_at = datetime.datetime.now(datetime.UTC)
    handle_db_transaction(session)
    return response_model(message="Please check your email for temporary password")


@router.post("/password/reset", tags=["Authentication"])
def reset_password(token=Form(), new_password=Form(), confirm_password=Form()):
    decoded_token = auth.decode_otp_jwt(token)
    email = decoded_token["user_identifier"]
    if new_password != confirm_password:
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message="Different Password",
                error="New password and confirm password must be same",
            ),
        )
    result = User.reset_password(email, new_password)
    return response_model(message=result)


@router.post("/user/login", tags=["User"])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@router.get(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("view_user"))]
)
async def get_all_users(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    id: int | None = None,
    email: str | None = None,
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if id:
        user_info = User.from_id(id)
        return response_model(data=user_info)
    if email:
        user_info = User.from_email(email)
        return response_model(data=user_info)
    result, count = User.get_all(page_number=page_number, page_size=page_size)
    final_page = ceil(count / page_size)
    next_page, previous_page = None, None
    if page_size * page_number < count:
        next_page = f"/api/v1/user?page_number={page_number+1}&page_size={page_size}"
    if page_number > 1:
        if page_number > final_page:
            previous_page = (
                f"/api/v1/user?page_number={final_page}&page_size={page_size}"
            )
        else:
            previous_page = (
                f"/api/v1/user?page_number={page_number-1}&page_size={page_size}"
            )
    return response_model(
        data={
            "pagination": {
                "total": count,
                "page_number": page_number,
                "page_Size": page_size,
                "next_page": next_page,
                "previous_page": previous_page,
                "final_page": final_page,
            },
            "result": result,
        }
    )


@router.post(
    "/user",
    status_code=201,
    tags=["User"],
    dependencies=[Depends(PermissionChecker("create_user"))],
)
async def add_user(
    userAddModel: UserAddModel, request: Request, backgroundTasks: BackgroundTasks
):
    await log_request(request)
    password, username, response = User.add(**userAddModel.model_dump())
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=userAddModel.email,
        username=username,
        password=password,
    )
    return response


@router.patch(
    "/user/{email}",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("update_user"))],
)
async def update_user(
    userUpdateModel: UserUpdateModel, request: Request, email: EmailStr
):
    await log_request(request)
    user_to_update = User.from_email(email)
    return response_model(
        message=User.update(user_to_update, **userUpdateModel.model_dump())
    )


@router.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return response_model(message=User.delete(**userDeleteModel.model_dump()))


@router.get("/user/me", tags=["User"])
async def my_info(token=Depends(auth.validate_token)):
    return response_model(data=User.from_email(token["user_identifier"]))


@router.get("/user/record", tags=["User"])
async def my_records(email):
    user_object = User.from_email(email)
    user_id = user_object.id
    return response_model(
        message="Successful", data=DeviceRequestRecord.user_record(user_id)
    )


@router.post("/user/change-password", tags=["User"])
def update_password(
    changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)
):
    return response_model(
        message=User.change_password(
            email=token.get("user_identifier"), **changePasswordModel.model_dump()
        )
    )


@router.get("/user/current-device", tags=["User"])
async def current_device(token: str = Depends(auth.validate_token)):
    email = token["user_identifier"]
    current_device = User.current_device(email)
    return response_model(data=current_device)


@router.get(
    "/user/{id}/current-device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_devices_user_id(id: int):
    current_devices = User.current_devices_by_user_id(id)
    return current_devices


@router.post("/user/refresh-token", tags=["User"], status_code=201)
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodeRefreshJWT(refreshToken.token)
    if token:
        return response_model(data={"access_token": token})
    raise HTTPException(
        status_code=401,
        detail={
            "Error": {
                "error_type": constants.TOKEN_ERROR,
                "error_message": constants.TOKEN_VERIFICATION_FAILED,
            }
        },
    )
