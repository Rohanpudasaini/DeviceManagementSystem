import datetime
from apps.device.enum import DeviceStatus, DeviceType, Purpose
from core.pydantic import BaseSchema


class DeviceAddModel(BaseSchema):
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


class DeviceRequestModel(BaseSchema):
    mac_address: str
    return_date: datetime.datetime = datetime.datetime.now(
        tz=datetime.UTC
    ) + datetime.timedelta(days=30)


class DeviceReturnModel(BaseSchema):
    mac_address: str


class DeviceRequestResultModel(BaseSchema):
    id_of_request: int


class DeviceMaintenanceModel(BaseSchema):
    purpose: Purpose
    description: str
    cost: float | None = None
    sent_for_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceReturnFromMaintenanceModel(BaseSchema):
    cost: float
    returned_from_repair: datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceUpdateModel(BaseSchema):
    name: str | None = None
    brand: str | None = None
    price: float | None = None
    description: str | None = None
    status: DeviceStatus | None = None
    product_images: list[str] | None = None
    specification: list[str] | None = None
