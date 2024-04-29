import datetime
from fastapi import Depends, Form, HTTPException, BackgroundTasks
from core.db import get_session, handle_db_transaction
from apps.device.models import User
from apps.authentication import auth
from core import constants
from core.logger import logger
from core.email import send_mail
from core.utils import (
    generate_password,
    response_model,
)


from apps.authentication.schemas import (
    ChangePasswordModel,
    LoginModel,
    RefreshTokenModel,
    ResetPasswordModel,
)


from fastapi import APIRouter

router = APIRouter()


@router.post("/login", tags=["Authentication"])
async def login(
    loginModel: LoginModel,
    session=Depends(get_session),
):
    user_object = User.from_email(session, loginModel.email)
    return User.login(session, user_object, **loginModel.model_dump(exclude_unset=True))


@router.post("/login/refresh-token", tags=["Authentication"], status_code=201)
async def get_new_access_token(refreshToken: RefreshTokenModel):
    token = auth.decode_refresh_jwt(refreshToken.token)
    if token:
        return response_model(data={"access_token": token})
    raise HTTPException(
        status_code=401,
        detail=response_model(message = constants.TOKEN_ERROR,
                error = constants.TOKEN_VERIFICATION_FAILED
    ))


@router.post("/change-password", tags=["Password"])
async def update_password(
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
async def reset_password(
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
    result = User.reset_password(session, user, new_password)
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
