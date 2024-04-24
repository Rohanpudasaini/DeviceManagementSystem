from pydantic import EmailStr
from apps.user.enum import Designation, RoleType
from core.pydantic import BaseSchema


class RefreshTokenModel(BaseSchema):
    token: str


class UserAddModel(BaseSchema):
    email: EmailStr
    first_name: str
    last_name: str
    phone_no: str | None = None
    address: str | None = None
    city: str | None = None
    postal_code: str | None = None
    designation: Designation = Designation.developer
    profile_pic_url: str | None = None
    role: RoleType | None = RoleType.viewer

class UserUpdateModel(BaseSchema):
    first_name: str | None = None
    last_name: str | None = None
    phone_no: str | None = None
    address: str | None = None
    city: str | None = None
    postal_code: str | None = None
    allow_notification: bool | None = None
    designation: Designation | None = None
    profile_pic_url: str | None = None
    role: RoleType | None = RoleType.viewer

class LoginModel(BaseSchema):
    email: EmailStr
    password: str


class ChangePasswordModel(BaseSchema):
    old_password: str
    new_password: str


class ResetPasswordModel(BaseSchema):
    email: EmailStr

