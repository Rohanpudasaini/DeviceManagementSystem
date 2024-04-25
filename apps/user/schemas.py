from pydantic import EmailStr
from core.pydantic import BaseSchema
from apps.user.enum import Designation, RoleType


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
