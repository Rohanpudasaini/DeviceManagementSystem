import time
from typing import Annotated
from fastapi import HTTPException
from jose import jwt, JWTError
import bcrypt
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from core.utils import response_model
from core import constants
from core.config import config

contain_header = HTTPBearer(auto_error=False)


def generate_jwt(
    email: str,
):
    payload = {
        "user_identifier": email,
        "expiry": time.time() + 1200,
    }
    encoded_access = jwt.encode(
        payload, config.secret_access, algorithm=config.algorithm
    )
    payload = {"user_identifier": email, "expiry": time.time() + 604800}
    encoded_refresh = jwt.encode(payload, config.secret_refresh, config.algorithm)
    return encoded_access, encoded_refresh


def decode_access_jwt(token: str):
    try:
        decode_token = jwt.decode(token, config.secret_access, config.algorithm)
        if decode_token["expiry"] >= time.time():
            return decode_token
        else:
            raise HTTPException(
                status_code=401,
                detail=response_model(
                    message=constants.TOKEN_ERROR,
                    error=constants.INVALID_TOKEN_SCHEME,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail=response_model(
                message=constants.TOKEN_ERROR,
                error=constants.TOKEN_VERIFICATION_FAILED,
            ),
        )


def decode_refresh_jwt(token: str):
    try:
        decode_token = jwt.decode(token, config.secret_refresh, config.algorithm)
        if decode_token["expiry"] >= time.time():
            new_token, _ = generate_jwt(decode_token["user_identifier"])
            return new_token
        else:
            raise HTTPException(
                status_code=401,
                detail=response_model(
                    message=constants.TOKEN_ERROR,
                    error=constants.EXPIRED_TOKEN,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail=response_model(
                message=constants.TOKEN_ERROR,
                error=constants.TOKEN_VERIFICATION_FAILED,
            ),
        )


def generate_otp_jwt(email: str):
    payload = {
        "user_identifier": email,
        "expiry": time.time() + 1240,
    }
    encoded_otp = jwt.encode(payload, config.otp_secret, algorithm=config.algorithm)
    return encoded_otp


def decode_otp_jwt(token: str):
    try:
        decode_token = jwt.decode(
            token=token, key=config.otp_secret, algorithms=config.algorithm
        )
        if decode_token["expiry"] >= time.time():
            return decode_token
        else:
            raise HTTPException(
                status_code=401,
                detail=response_model(
                    message=constants.TOKEN_ERROR,
                    error=constants.EXPIRED_TOKEN,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            # detail=
            detail=response_model(
                message=constants.TOKEN_ERROR,
                error=constants.TOKEN_VERIFICATION_FAILED,
            ),
        )


def hash_password(password):
    pwd_bytes = password.encode("UTF-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password.decode()


def verify_password(plain_password: str, hashed_password):
    password_byte_enc = plain_password.encode("utf-8")
    hashed_password = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_byte_enc, hashed_password)


def validate_token(
    token: Annotated[HTTPAuthorizationCredentials, Depends(contain_header)],
):
    if token:
        return decode_access_jwt(token.credentials)
    raise HTTPException(
        status_code=401,
        detail=response_model(
            message=constants.TOKEN_ERROR,
            error=constants.TOKEN_VERIFICATION_FAILED,
        ),
    )
