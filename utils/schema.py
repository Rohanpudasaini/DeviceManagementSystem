from enum import Enum
from pydantic import BaseModel, ConfigDict, EmailStr
import datetime


class Purpose(Enum):
    REPAIR = "repair"
    UPGRADE = "upgrade"
    EXCHANGE = "exchange"


class Designation(Enum):
    ADMIN = "admin"
    DEVICE_MANAGER = "device_manager"
    STAFF = "staff"
    VIEWER = "viewer"


class DeviceType(Enum):
    LAPTOP = "laptop"
    TABLET = "lablet"
    PHONE = "phone"
    DESKTOP = "desktop"


class DeviceStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class RefreshTokenModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


class UserAddModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    first_name: str
    last_name: str
    phone_no: str | None = None
    address: str | None = None
    city: str | None = None
    postal_code: str | None = None
    designation: Designation = Designation.VIEWER
    profile_pic_url: str | None = None
    role: list[str] = ["Viewer"]


class DeviceAddModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
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


class DeviceRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac_address: str


class DeviceMaintainanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: Purpose
    description: str
    cost: float | None = None
    mac_address: str
    email:EmailStr
    sent_for_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceReturnFromMaintainanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac_address: str
    cost: float
    returned_from_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceUpdateModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac_address:str
    name: str | None = None
    brand: str | None = None
    price: float | None = None
    description: str | None = None
    status: DeviceStatus | None = None
    product_images: list[str] | None = None
    specification: list[str] | None = None


class UserUpdateModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr 
    first_name: str | None = None
    last_name: str | None = None
    phone_no: str | None = None
    address: str | None = None
    city: str | None = None
    postal_code: str | None = None
    allow_notification: bool | None = None
    designation: Designation | None = None
    profile_pic_url: str | None = None
    role: list[str] | None = ["Viewer"]


class DeleteModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier: str


class LoginModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str


class ChangePasswordModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_password: str
    new_password: str
