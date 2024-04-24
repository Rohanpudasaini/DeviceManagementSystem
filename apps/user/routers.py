
import datetime
from math import ceil
from fastapi import Depends, Form, HTTPException, Request, BackgroundTasks
from pydantic import EmailStr
from core.db import handle_db_transaction, session
from apps.device.models import DeviceRequestRecord, User
from auth import auth
from auth.permissions import PermissionChecker
from core import constants
from core.email import send_mail
from core.utils import (
    check_for_null_or_deleted,
    error_response,
    generate_password,
    log_request,
    normal_response,
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

from main import api_v1



@api_v1.get(
    "/user",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("view_user"))]
)
async def get_all_users(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    id: int | None = None,
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if id:
        user_info = User.from_id(id)
        check_for_null_or_deleted(user_info, "id", "user")
        return normal_response(data=user_info)
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
    return normal_response(
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


@api_v1.post(
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


@api_v1.patch(
    "/user/{email}",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("update_user"))],
)
async def update_user(
    userUpdateModel: UserUpdateModel, request: Request, email: EmailStr
):
    await log_request(request)
    return normal_response(message=User.update(email, **userUpdateModel.model_dump()))


@api_v1.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=User.delete(**userDeleteModel.model_dump()))


@api_v1.get("/user/me", tags=["User"])
async def my_info(token=Depends(auth.validate_token)):
    return normal_response(data=User.from_email(token["user_identifier"]))


@api_v1.get("/user/record/", tags=["User"])
async def user_records(email):
    user_object = User.from_email(email)
    check_for_null_or_deleted(user_object)

    user_id = user_object.id

    return normal_response(
        message="Successful", data=DeviceRequestRecord.user_record(user_id)
    )


@api_v1.post("/user/change-password", tags=["User"])
def update_password(
    changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)
):
    return normal_response(
        message=User.change_password(
            email=token.get("user_identifier"), **changePasswordModel.model_dump()
        )
    )


@api_v1.get("/user/current-device", tags=["User"])
async def current_device(token: str = Depends(auth.validate_token)):
    current_device = User.current_device(token)
    return normal_response(data=current_device)


@api_v1.get(
    "/user/{id}/current-device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_devices_user_id(id: int):
    current_devices = User.current_devices_by_user_id(id)
    return current_devices


@api_v1.post("/password/reset", tags=["Authentication"])
def reset_password(token=Form(), new_password=Form(), confirm_password=Form()):
    email = auth.decode_otp_jwt(token)
    email = email["user_identifier"]
    result = User.reset_password(email, new_password, confirm_password)
    if result:
        return normal_response(message="Your password has been successfully updated.")


@api_v1.post("/user/login", tags=["User"])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@api_v1.post("/user/refresh-token", tags=["User"], status_code=201)
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodeRefreshJWT(refreshToken.token)
    if token:
        return normal_response(data={"access_token": token})
    raise HTTPException(
        status_code=401,
        detail={
            "Error": {
                "error_type": constants.TOKEN_ERROR,
                "error_message": constants.TOKEN_VERIFICATION_FAILED,
            }
        },
    )


@api_v1.post("/password/forget", tags=["Authentication"])
async def forget_password(
    resetPassword: ResetPasswordModel, backgroundTasks: BackgroundTasks
):
    user_object = User.from_email(resetPassword.email)
    if not user_object:
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found("user", "email"),
            ),
        )
    password = generate_password(12)
    backgroundTasks.add_task(
        send_mail.reset_mail,
        email_to_send_to=resetPassword.email,
        username=user_object.full_name,
        password=password,
    )
    # user_object.
    user_object.temp_password = auth.hash_password(password)
    user_object.temp_password_created_at = datetime.datetime.now(datetime.UTC)
    handle_db_transaction(session)
    return normal_response(message="Please check your email for temporary password")

