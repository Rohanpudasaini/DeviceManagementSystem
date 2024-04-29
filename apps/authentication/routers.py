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
    data: LoginModel,
    session=Depends(get_session),
):
    """
    Authenticates a user based on the provided email and password encapsulated within `data` 
    from the request body. This asynchronous endpoint handles user login, validating the 
    credentials and returning the appropriate response.

    This function leverages FastAPI's dependency injection system to handle the database session, 
    and expects the user's login details to be passed as a JSON object that conforms to the 
    `LoginModel` schema.

    Parameters:
    - data (LoginModel): An object containing the user's email and password, received from the request body.
    - session (Session): A database session provided by FastAPI's dependency injection system. This session
      is used to handle all database transactions involved in the authentication process.

    Returns:
    - dict: A dictionary representing the authentication status of the user, which could include user information 
      and authentication tokens if the login is successful, or error messages if it is not.

    Raises:
    - HTTPException: An error response with an appropriate status code and message if the authentication fails 
      for reasons such as incorrect credentials or server issues.
    """
    user_object = User.from_email(session, data.email)
    return User.login(session, user_object, **data.model_dump(exclude_unset=True))


@router.post("/login/refresh-token", tags=["Authentication"], status_code=201)
async def get_new_access_token(data: RefreshTokenModel):
    """
    Generates a new access token from a provided refresh token.

    This asynchronous endpoint receives a refresh token encapsulated within `data` from the request body
    and attempts to decode it to issue a new access token. If the refresh token is valid, a new access token
    is returned in the response. If the token is invalid or expired, it raises an HTTPException with status code 401.

    Parameters:
    - data (RefreshTokenModel): An object containing the `token` field with the refresh token, received from the request body.

    Returns:
    - dict: A dictionary containing the new `access_token` if the refresh token is successfully decoded.

    Raises:
    - HTTPException: An error response with status code 401 and detailed message if the refresh token
      is invalid or fails verification.
    """
    token = auth.decode_refresh_jwt(data.token)
    if token:
        return response_model(data={"access_token": token})
    raise HTTPException(
        status_code=401,
        detail=response_model(
            message=constants.TOKEN_ERROR, error=constants.TOKEN_VERIFICATION_FAILED
        ),
    )


@router.post("/change-password", tags=["Password"])
async def update_password(
    data: ChangePasswordModel,
    token=Depends(auth.validate_token),
    session=Depends(get_session),
):
    """
    Updates a user's password if the old password matches and the new password is different.

    This endpoint processes a password change request after validating the user's current (old) password
    and ensuring the new password is not the same as the current one. The user is identified using a token,
    which must be valid and active. If the old password doesn't match or if the new password is the same
    as the old, an HTTPException is raised with a status code of 409.

    Parameters:
    - data (ChangePasswordModel): An object containing the old and new passwords from the request body.
    - token (dict): A dictionary extracted from the user's access token via dependency injection.
    - session (Session): A database session to handle transaction with the database.

    Returns:
    - dict: A dictionary containing a message about the successful password update.

    Raises:
    - HTTPException: An error response with status code 409 indicating either mismatch of old password
      or if the new password is the same as the current password. The detailed error message will be provided.
    """
    user_to_update = User.from_email(session, token.get("user_identifier"))
    if not auth.verify_password(data.old_password, user_to_update.password):
        logger.warning("Password don't match")
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.UNAUTHORIZED,
                error=constants.UNAUTHORIZED_MESSAGE,
            ),
        )
    if auth.verify_password(data.new_password, user_to_update.password):
        logger.warning("Same password as old password")
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message="Same Password",
                error="New password same as old password",
            ),
        )
    return response_model(
        message=User.change_password(session, user_to_update, data.new_password)
    )


@router.post("/reset-password", tags=["Password"])
async def reset_password(
    token=Form(),
    new_password=Form(),
    confirm_password=Form(),
    session=Depends(get_session),
):
    """
    Resets a user's password given a valid OTP (One-Time Password) token and matching new passwords.

    This endpoint handles password reset requests where the user has already verified their identity
    through an OTP sent to their registered email. The password reset process involves validating
    the OTP token, checking the match between the new password and its confirmation, and updating
    the password in the database.

    Parameters:
    - token (str): The OTP token provided by the user, used to validate their identity.
    - new_password (str): The new password the user wishes to set.
    - confirm_password (str): A confirmation of the new password for validation purposes.
    - session (Session): A database session to handle transactions with the database.

    Returns:
    - dict: A dictionary containing a success message indicating that the password has been updated.

    Raises:
    - HTTPException: An error response with status code 400 if the new password and confirm password do not match,
      or other status codes as appropriate for other failure conditions (e.g., invalid token).
    """
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
    data: ResetPasswordModel,
    backgroundTasks: BackgroundTasks,
    session=Depends(get_session),
):
    """
    Initiates a password reset process by sending a temporary password to the user's email.

    This endpoint generates and sends a new temporary password to the user specified by the email
    in the `ResetPasswordModel`. It verifies the existence of the user in the database, creates
    a new hashed temporary password, and sends it via email asynchronously. The temporary password
    and its creation time are updated in the database for further verification during the login process.

    Parameters:
    - data (ResetPasswordModel): The model containing the email of the user requesting a password reset.
    - backgroundTasks (BackgroundTasks): Task manager for running operations in the background.
    - session (Session): Database session for handling transactions.

    Returns:
    - dict: A dictionary containing a success message instructing the user to check their email for the temporary password.

    Raises:
    - HTTPException: An error response with status code 404 if no user is found with the given email.
    """
    user_object = User.from_email(session, data.email)
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
        email_to_send_to=data.email,
        username=user_object.full_name,
        password=password,
    )
    # user_object.
    user_object.temp_password = auth.hash_password(password)
    user_object.temp_password_created_at = datetime.datetime.now(datetime.UTC)
    handle_db_transaction(session)
    return response_model(message="Please check your email for temporary password")
