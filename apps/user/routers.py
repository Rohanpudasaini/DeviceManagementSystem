import datetime
from math import ceil
from fastapi import Depends, Form, HTTPException, Request, BackgroundTasks
from pydantic import EmailStr
from sqlalchemy import Select
from core.db import get_session, handle_db_transaction
from apps.device.models import DeviceRequestRecord, User
from auth import auth
from auth.permissions import PermissionChecker
from core import constants
from core.logger import logger
from core.email import send_mail
from core.utils import (
    generate_password,
    log_request,
    response_model,
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


from fastapi import APIRouter

router = APIRouter(prefix="")


@router.post("/login", tags=["Authentication"])
async def login(
    loginModel: LoginModel,
    session=Depends(get_session),
):
    user_object = User.from_email(session, loginModel.email)
    return User.login(session, user_object, **loginModel.model_dump())


@router.post("/login/refresh-token", tags=["Authentication"], status_code=201)
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


@router.post("/change-password", tags=["Password"])
def update_password(
    changePasswordModel: ChangePasswordModel,
    token=Depends(auth.validate_token),
    session=Depends(get_session),
):
    user_to_update = User.from_email(session, token.get("user_identifier"))
    if not auth.verify_password(
        changePasswordModel.old_password, user_to_update.password
    ):
        logger.warning("Password don't match")
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.UNAUTHORIZED,
                error=constants.UNAUTHORIZED_MESSAGE,
            ),
        )
    if auth.verify_password(changePasswordModel.new_password, user_to_update.password):
        logger.warning("Same password as old password")
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message="Same Password",
                error="New password same as old password",
            ),
        )
    return response_model(
        message=User.change_password(
            session, user_to_update, changePasswordModel.new_password
        )
    )


@router.post("/reset-password", tags=["Password"])
def reset_password(
    token=Form(),
    new_password=Form(),
    confirm_password=Form(),
    session=Depends(get_session),
):
    if new_password != confirm_password:
        raise HTTPException(
            status_code=400,
            detail=response_model(
                message="Bad Request", error="The password do not match"
            ),
        )
    email = auth.decode_otp_jwt(token)
    email = email["user_identifier"]
    user = User.from_email(session, email)
    result = User.reset_password(session, user, new_password, confirm_password)
    if result:
        return response_model(message="Your password has been successfully updated.")


@router.post("/forget-password", tags=["Password"])
async def forget_password(
    resetPassword: ResetPasswordModel,
    backgroundTasks: BackgroundTasks,
    session=Depends(get_session),
):
    user_object = User.from_email(session, resetPassword.email)
    if not user_object:
        raise HTTPException(
            status_code=404,
            detail=response_model(
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
    return response_model(message="Please check your email for temporary password")


@router.get(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("view_user"))]
)
async def get_all_users(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    id: int | None = None,
    session=Depends(get_session),
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if id:
        user_info = User.from_id(session, id)
        return response_model(data=user_info)
    result, count = User.get_all(
        session=session, page_number=page_number, page_size=page_size
    )
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
    userAddModel: UserAddModel,
    request: Request,
    backgroundTasks: BackgroundTasks,
    session=Depends(get_session),
):
    await log_request(request)
    password, username, response = User.add(session, **userAddModel.model_dump())
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
    userUpdateModel: UserUpdateModel,
    request: Request,
    email: EmailStr,
    session=Depends(get_session),
):
    await log_request(request)
    user_to_update = User.from_email(session, email)
    return response_model(
        message=User.update(user_to_update, session, **userUpdateModel.model_dump())
    )


@router.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(
    userDeleteModel: DeleteModel,
    request: Request,
    session=Depends(get_session),
):
    await log_request(request)
    user_to_delete = User.from_email(session, userDeleteModel.identifier)
    if user_to_delete.devices:
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message="Conflict",
                error="The user have some devices assigned to them, can't delete the user",
            ),
        )
    return response_model(message=User.delete(session, user_to_delete))


@router.get("/user/me", tags=["User"])
async def my_info(session=Depends(get_session), token=Depends(auth.validate_token)):
    return response_model(data=User.from_email(session, token["user_identifier"]))


@router.get("/user/record", tags=["User"])
async def user_records(
    email,
    session=Depends(get_session),
):
    user_object = User.from_email(session, email)
    user_id = user_object.id
    return response_model(
        message="Successful",
        data=session.scalars(
            Select(DeviceRequestRecord).where(DeviceRequestRecord.user_id == user_id)
        ).all(),
        # message="Successful", data=DeviceRequestRecord.user_record(session,user_id)
    )


@router.get("/user/current-device", tags=["User"])
async def current_device(
    token: str = Depends(auth.validate_token), session=Depends(get_session)
):
    user = User.from_email(session, token["user_identifier"])
    current_device = user.devices
    if not current_device:
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=f"No device is associated with the {user.full_name}",
            ),
        )
    return response_model(data=current_device)


@router.get(
    "/user/{id}/current-device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_devices_user_id(id: int, session=Depends(get_session)):
    user = User.from_id(session, id)
    current_devices = user.devices
    if not current_device:
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=f"No device is associated with the {user.full_name}",
            ),
        )
    current_devices = User.current_devices_by_user_id(id)
    return current_devices
