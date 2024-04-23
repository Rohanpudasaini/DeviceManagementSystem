from enum import Enum
from pydantic import BaseModel, ConfigDict, EmailStr
import datetime

class UpdatedBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Purpose(Enum):
    REPAIR = "repair"
    UPGRADE = "upgrade"
    EXCHANGE = "exchange"


class RoleType(Enum):
    admin = "admin"
    device_manager = "device_manager"
    staff = "staff"
    viewer = "viewer"


class DeviceType(Enum):
    LAPTOP = "laptop"
    TABLET = "tablet"
    PHONE = "phone"
    DESKTOP = "desktop"


class DeviceStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class Designation(Enum):
    manager = "manager"
    developer = "developer"
    hr = "hr"
    it_support = "it_support"
    ceo = "ceo"
    viewer = "viewer"


class RefreshTokenModel(UpdatedBaseModel):
    token: str


class UserAddModel(UpdatedBaseModel):
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


class DeviceAddModel(UpdatedBaseModel):
    name: str
    brand: str
    price: float
    mac_address: str
    description: str | None = None
    status: DeviceStatus = DeviceStatus.ACTIVE
    bill_image: str
    product_images: list[str] | None = None
    type: DeviceType = DeviceType.LAPTOP
    specification: list[str] | None = None
    purchase_date: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceRequestModel(UpdatedBaseModel):
    mac_address: str


class DeviceMaintenanceModel(UpdatedBaseModel):
    purpose: Purpose
    description: str
    cost: float | None = None
    mac_address: str
    sent_for_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceReturnFromMaintenanceModel(UpdatedBaseModel):
    cost: float
    returned_from_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceUpdateModel(UpdatedBaseModel):
    name: str | None = None
    brand: str | None = None
    price: float | None = None
    description: str | None = None
    status: DeviceStatus | None = None
    product_images: list[str] | None = None
    specification: list[str] | None = None


class UserUpdateModel(UpdatedBaseModel):
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


class DeleteModel(UpdatedBaseModel):
    identifier: str


class LoginModel(UpdatedBaseModel):
    email: EmailStr
    password: str


class ChangePasswordModel(UpdatedBaseModel):
    old_password: str
    new_password: str


class ResetPasswordModel(UpdatedBaseModel):
    email: EmailStr
