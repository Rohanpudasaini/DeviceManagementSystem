import time
from typing import Annotated
from fastapi import HTTPException
from jose import jwt, JWTError
import os
import bcrypt
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from core.utils import error_response
from core import constants

contain_header = HTTPBearer(auto_error=False)

ACCESS_SECRET = os.getenv("SECRET_ACCESS")
REFRESH_SECRET = os.getenv("SECRET_REFRESH")
ALGORITHM = os.getenv("ALGORITHM")
OTP_SECRET = os.getenv("OTP_SECRET")


def generate_JWT(
    email: str,
):
    payload = {
        "user_identifier": email,
        "expiry": time.time() + 1200,
        # 'expiry': time.time() + 240
    }
    encoded_access = jwt.encode(payload, ACCESS_SECRET, algorithm=ALGORITHM)
    payload = {"user_identifier": email, "expiry": time.time() + 604800}
    encoded_refresh = jwt.encode(payload, REFRESH_SECRET, ALGORITHM)
    return encoded_access, encoded_refresh


def decodeAccessJWT(token: str):
    try:
        decode_token = jwt.decode(token, ACCESS_SECRET, ALGORITHM)
        # return decode_token if decode_token['expiry'] >= time.time() else None
        if decode_token["expiry"] >= time.time():
            return decode_token
        else:
            raise HTTPException(
                status_code=401,
                detail=error_response(
                    message=constants.TOKEN_ERROR,
                    error=constants.INVALID_TOKEN_SCHEME,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail=error_response(
                message=constants.TOKEN_ERROR,
                error=constants.TOKEN_VERIFICATION_FAILED,
            ),
        )


def decodeRefreshJWT(token: str):
    try:
        decode_token = jwt.decode(token, REFRESH_SECRET, ALGORITHM)
        # return decode_token if decode_token['expiry'] >= time.time() else None
        if decode_token["expiry"] >= time.time():
            new_token, _ = generate_JWT(decode_token["user_identifier"])
            return new_token
        else:
            raise HTTPException(
                status_code=401,
                detail=error_response(
                    message=constants.TOKEN_ERROR,
                    error=constants.EXPIRED_TOKEN,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            # detail=
            detail=error_response(
                message=constants.TOKEN_ERROR,
                error=constants.TOKEN_VERIFICATION_FAILED,
            ),
        )


def generate_otp_JWT(email: str):
    payload = {
        "user_identifier": email,
        # 'expiry': time.time() + 1200
        "expiry": time.time() + 1240,
    }
    encoded_otp = jwt.encode(payload, OTP_SECRET, algorithm=ALGORITHM)
    return encoded_otp


def decode_otp_jwt(token: str):
    try:
        decode_token = jwt.decode(token=token, key=OTP_SECRET, algorithms=ALGORITHM)
        if decode_token["expiry"] >= time.time():
            return decode_token
        else:
            raise HTTPException(
                status_code=401,
                detail=error_response(
                    message=constants.TOKEN_ERROR,
                    error=constants.EXPIRED_TOKEN,
                ),
            )
    except JWTError:
        raise HTTPException(
            status_code=401,
            # detail=
            detail=error_response(
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
    token: Annotated[HTTPAuthorizationCredentials, Depends(contain_header)]
):
    if token:
        return decodeAccessJWT(token.credentials)
    raise HTTPException(
        status_code=401,
        detail=error_response(
            message=constants.TOKEN_ERROR,
            error=constants.TOKEN_VERIFICATION_FAILED,
        ),
    )
