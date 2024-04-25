from pydantic import EmailStr
from core.pydantic import BaseSchema


class LoginModel(BaseSchema):
    email: EmailStr
    password: str


class RefreshTokenModel(BaseSchema):
    token: str


class ChangePasswordModel(BaseSchema):
    old_password: str
    new_password: str


class ResetPasswordModel(BaseSchema):
    email: EmailStr
