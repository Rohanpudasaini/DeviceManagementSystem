from math import ceil
from fastapi import Depends, Request, APIRouter
from apps.device.models import Device, DeviceRequestRecord, MaintenanceHistory
from auth import auth
from auth.permissions import PermissionChecker
from core import constants
from core.logger import logger
from core.utils import (
    response_model,
    log_request,
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

router = APIRouter(prefix='/device')


@router.get(
    "/categories",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
async def categories():
    return response_model(data=[i for i in DeviceType])


@router.get(
    "", tags=["Device"], dependencies=[Depends(PermissionChecker("view_device"))]
)
async def get_all_device(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    mac_address: str | None = None,
    name: str | None = None,
    brand: str | None = None,
    category: str | None = None,
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if category:
        result = Device.from_category(category)
        count = len(result)
        return response_model(data={"pagination": {"total": count}, "result": result})
    if mac_address:
        device_info = Device.from_mac_address(mac_address)
        return response_model(data=device_info)
    if name or brand:
        device = Device.search_device(name, brand)
        if device:
            count = len(device)
            logger.info({"pagination": {"total": count}, "result": device})
            return response_model(
                data={"pagination": {"total": count}, "result": device}
            )
        else:
            return response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found("Device", "Brand or Name"),
            )

    result, count = Device.get_all(page_number=page_number, page_size=page_size)
    final_page = ceil(count / page_size)
    if result:
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

    return response_model(
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


@router.post(
    "",
    tags=["Device"],
    status_code=201,
    dependencies=[Depends(PermissionChecker("create_device"))],
)
async def add_device(deviceAddModel: DeviceAddModel, request: Request):
    await log_request(request)
    return response_model(message=Device.add(**deviceAddModel.model_dump()))


@router.patch(
    "/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("update_device"))],
)
async def update_device(
    deviceUpdateModel: DeviceUpdateModel, request: Request, mac_address: str
):
    await log_request(request)
    return response_model(
        message=Device.update(mac_address, **deviceUpdateModel.model_dump())
    )


@router.delete(
    "",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("delete_device"))],
)
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return response_model(message=Device.delete(deviceDeleteModel.identifier))


@router.post(
    "/request",
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
    return response_model(
        message=DeviceRequestRecord.allot_to_user(
            user_email=email, mac_address=deviceRequestModel.mac_address
        )
    )


@router.post(
    "/return",
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
    return response_model(
        message=DeviceRequestRecord.return_device(
            user_email=email, mac_address=deviceReturnModel.mac_address
        )
    )


@router.post(
    "/request-maintenance/{mac_address}",
    tags=["Device"],
    status_code=201,
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def request_maintenance(
    mac_address: str,
    deviceMaintenanceModel: DeviceMaintenanceModel,
    token=Depends(auth.validate_token),
):
    return response_model(
        message=MaintenanceHistory.add(
            mac_address=mac_address,
            email=token.get("user_identifier"),
            **deviceMaintenanceModel.model_dump(),
        )
    )


@router.patch(
    "/return-maintenance/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def return_maintenance(
    mac_address: str, deviceReturn: DeviceReturnFromMaintenanceModel
):
    return response_model(
        message=MaintenanceHistory.update(
            mac_address=mac_address, **deviceReturn.model_dump()
        )
    )


@router.get(
    "/{mac_address}/maintenance-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
def device_maintenance_history(mac_address: str):
    device_object = Device.from_mac_address(mac_address)
    device_id = device_object.id
    result = MaintenanceHistory.device_maintenance_history(device_id)
    return response_model(message="Successful", data=result)


@router.get(
    "/{mac_address}/owner-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
def device_owner_history(mac_address: str):
    device_object = Device.from_mac_address(mac_address)
    device_id = device_object.id
    result = DeviceRequestRecord.device_owner_history(device_id)
    return response_model(message="Successful", data=result)
