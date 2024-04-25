from math import ceil
from fastapi import Depends, HTTPException, Request, APIRouter
from apps.device.enum import DeviceStatus
from apps.device.models import Device, DeviceRequestRecord, MaintenanceHistory
from apps.user.models import User
from apps.authentication import auth
from apps.authentication.permissions import PermissionChecker
from core import constants
from core.db import get_session
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

router = APIRouter(prefix="/device")


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
    session=Depends(get_session),
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if category:
        result = Device.from_category(session, category)
        count = len(result)
        return response_model(data={"pagination": {"total": count}, "result": result})
    if mac_address:
        device_info = Device.from_mac_address(session, mac_address)
        return response_model(data=device_info)
    if name or brand:
        device = Device.search_device(session, name, brand)
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

    result, count = Device.get_all(
        session, page_number=page_number, page_size=page_size
    )
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
async def add_device(
    deviceAddModel: DeviceAddModel,
    request: Request,
    session=Depends(get_session),
):
    await log_request(request)
    mac_exist = Device.from_mac_address(session, deviceAddModel.mac_address)
    if not mac_exist:
        return response_model(
            message=Device.add(session, **deviceAddModel.model_dump())
        )
    raise HTTPException(
        status_code=409,
        details=response_model(
            message="Duplicate Value", error="Mac address already exist"
        ),
    )


@router.patch(
    "/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("update_device"))],
)
async def update_device(
    deviceUpdateModel: DeviceUpdateModel,
    request: Request,
    mac_address: str,
    session=Depends(get_session),
):
    await log_request(request)
    device_to_update = Device.from_mac_address(session, mac_address)
    return response_model(
        message=Device.update(
            session, device_to_update, **deviceUpdateModel.model_dump()
        )
    )


@router.delete(
    "",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("delete_device"))],
)
async def delete_device(
    deviceDeleteModel: DeleteModel,
    request: Request,
    session=Depends(get_session),
):
    await log_request(request)
    device_to_delete = Device.from_mac_address(session, deviceDeleteModel.identifier)
    return response_model(message=Device.delete(session, device_to_delete))


@router.post(
    "/request",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def request_device(
    deviceRequestModel: DeviceRequestModel,
    request: Request,
    token=Depends(auth.validate_token),
    session=Depends(get_session),
):
    await log_request(request)
    email = token.get("user_identifier")
    device_to_allot = Device.from_mac_address(session, deviceRequestModel.mac_address)
    requested_user = User.from_email(session, email)
    if not device_to_allot.available:
        logger.error("The device is no longer available")
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.INSUFFICIENT_RESOURCES,
                error=constants.insufficient_resources("device"),
            ),
        )
    if device_to_allot.status.value != "active":
        logger.error("The device with device id {device_id} is not active")
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found("device", "device id"),
            ),
        )
    return response_model(
        message=DeviceRequestRecord.allot_to_user(
            session, requested_user=requested_user, device_to_allot=device_to_allot
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
    session=Depends(get_session),
):
    await log_request(request)
    email = token.get("user_identifier")
    device_to_return = Device.from_mac_address(session, deviceReturnModel.mac_address)
    returned_user = User.from_email(session, email)
    return response_model(
        message=DeviceRequestRecord.return_device(
            session, returned_user=returned_user, device_to_return=device_to_return
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
    session=Depends(get_session),
):
    email = token.get("user_identifier")
    device_to_repair = Device.from_mac_address(session, mac_address)
    user = User.from_email(session, email)
    if (
        not device_to_repair.available
        or device_to_repair.status == DeviceStatus.INACTIVE
    ):
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message="Device In Maintenance",
                error="The device you have request for is in maintenance",
            ),
        )
    return response_model(
        message=MaintenanceHistory.add(
            session,
            device_to_repair=device_to_repair,
            user=user,
            **deviceMaintenanceModel.model_dump(),
        )
    )


@router.patch(
    "/return-maintenance/{mac_address}",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def return_maintenance(
    mac_address: str,
    deviceReturn: DeviceReturnFromMaintenanceModel,
    session=Depends(get_session),
):
    returned_device = Device.from_mac_address(session, mac_address)
    return response_model(
        message=MaintenanceHistory.update(
            session, returned_device=returned_device, **deviceReturn.model_dump()
        )
    )


@router.get(
    "/{mac_address}/maintenance-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
def device_maintenance_history(mac_address: str, session):
    device_object = Device.from_mac_address(session, mac_address)
    device_id = device_object.id
    result = MaintenanceHistory.device_maintenance_history(session, device_id)
    return response_model(message="Successful", data=result)


@router.get(
    "/{mac_address}/owner-history",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
def device_owner_history(
    mac_address: str,
    session=Depends(get_session),
):
    device_object = Device.from_mac_address(session, mac_address)
    device_id = device_object.id
    result = DeviceRequestRecord.device_owner_history(session, device_id)
    return response_model(message="Successful", data=result)
