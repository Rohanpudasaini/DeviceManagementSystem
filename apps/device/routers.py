
from math import ceil
from fastapi import Depends, Request
from apps.device.models import Device, DeviceRequestRecord, MaintenanceHistory
from auth import auth
from auth.permissions import PermissionChecker
from core import constants
from core.logger import logger
from core.utils import (
    check_for_null_or_deleted,
    error_response,
    log_request,
    normal_response,
)
from apps.device.schemas import (
    DeviceAddModel,
    DeviceMaintenanceModel,
    DeviceRequestModel,
    DeviceReturnFromMaintenanceModel,
    DeviceType,
    DeviceUpdateModel,
)
from core.pydantic import DeleteModel

from main import api_v1


@api_v1.get(
    "/device/categories",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))]
)
async def categories():
    return normal_response(data=[i for i in DeviceType])


@api_v1.get(
    "/device",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))]
)
async def get_all_device(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    mac_address: str | None = None,
    name: str | None = None,
    brand: str | None = None,
    category: str | None = None
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if category:
        result = Device.from_category(category)
        count = len(result)
        return normal_response(data={"pagination": {"total": count}, "result": result})
    if mac_address:
        device_info = Device.from_mac_address(mac_address)
        check_for_null_or_deleted(device_info, "mac_address", "device")
        return normal_response(data=device_info)
    if name or brand:
        device = Device.search_device(name, brand)
        if device:
            count = len(device)
            logger.info({"pagination": {"total": count}, "result": device})
            return normal_response(
                data={"pagination": {"total": count}, "result": device}
            )
        else:
            return error_response(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found(
                    "Device", "Brand or Name"),
            )

    result, count = Device.get_all(
        page_number=page_number, page_size=page_size)
    final_page = ceil(count / page_size)
    logger.info([singleresult.__dict__ for singleresult in result])
    next_page, previous_page = None, None
    if page_size * page_number < count:
        next_page = f"/api/v1/device?page_number={page_number+1}&page_size={page_size}"
    if page_number > 1:
        if page_number > final_page:
            previous_page = (
                f"/api/v1/device?page_number={final_page}&page_size={page_size}"
            )
        else:
            previous_page = (
                f"/api/v1/device?page_number={page_number-1}&page_size={page_size}"
            )

    return normal_response(
        data={
            "pagination": {
                "total": count,
                "page_number": page_number,
                "page_size": page_size,
                "next_page": next_page,
                "previous_page": previous_page,
                "final_page": final_page,
            },
            "result": result,
        }
    )


@api_v1.post(
    "/device",
    tags=["Device"],
    status_code=201,
    dependencies=[Depends(PermissionChecker("create_device"))],
)
async def add_device(deviceAddModel: DeviceAddModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.add(**deviceAddModel.model_dump()))


@api_v1.patch(
    "/device/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("update_device"))],
)
async def update_device(
    deviceUpdateModel: DeviceUpdateModel, request: Request, mac_address: str
):
    await log_request(request)
    return normal_response(
        message=Device.update(mac_address, **deviceUpdateModel.model_dump())
    )


@api_v1.delete(
    "/device",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("delete_device"))],
)
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.delete(**deviceDeleteModel.model_dump()))


@api_v1.post(
    "/device/request",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def request_device(
    deviceRequestModel: DeviceRequestModel,
    request: Request,
    token=Depends(auth.validate_token),
):
    await log_request(request)
    email = token.get("user_identifier")
    return normal_response(
        message=DeviceRequestRecord.allot_to_user(
            user_email=email, mac_address=deviceRequestModel.mac_address
        )
    )


@api_v1.post(
    "/device/return",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def return_device(
    deviceReturnModel: DeviceRequestModel,
    request: Request,
    token=Depends(auth.validate_token),
):
    await log_request(request)
    email = token.get("user_identifier")
    return normal_response(
        message=DeviceRequestRecord.return_device(
            user_email=email, mac_address=deviceReturnModel.mac_address
        )
    )


@api_v1.post(
    "/device/request-maintenance/{mac_address}",
    tags=["Device"],
    status_code=201,
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def request_maintenance(
    mac_address: str,
    deviceMaintenanceModel: DeviceMaintenanceModel,
    token=Depends(auth.validate_token),
):
    return normal_response(
        message=MaintenanceHistory.add(
            mac_address=mac_address,
            email=token.get("user_identifier"),
            **deviceMaintenanceModel.model_dump(),
        )
    )


@api_v1.patch(
    "/device/return-maintenance/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def return_maintenance(
    mac_address: str, deviceReturn: DeviceReturnFromMaintenanceModel
):
    return normal_response(
        message=MaintenanceHistory.update(
            mac_address=mac_address, **deviceReturn.model_dump()
        )
    )


@api_v1.get(
    "/device/{mac_address}/maintenance-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))]
    )
def device_maintenance_history(mac_address: str):
    device_object = Device.from_mac_address(mac_address)
    check_for_null_or_deleted(device_object)
    device_id = device_object.id
    result = MaintenanceHistory.device_maintenance_history(device_id)
    return normal_response(
        message="Successful",
        data=result)


@api_v1.get(
    "/device/{mac_address}/owner-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))]
    )
def device_owner_history(mac_address: str):
    device_object = Device.from_mac_address(mac_address)
    check_for_null_or_deleted(device_object)
    device_id = device_object.id
    result = DeviceRequestRecord.device_owner_history(device_id)
    return normal_response(
        message="Successful",
        data=result)

