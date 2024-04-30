from math import ceil
from fastapi import Depends, HTTPException, Request, BackgroundTasks
from pydantic import EmailStr
from sqlalchemy import Select
from core.db import get_session
from apps.device.models import DeviceRequestRecord, User
from apps.authentication import auth
from apps.authentication.permissions import PermissionChecker
from core import constants
from core.email import send_mail
from core.utils import (
    log_request,
    response_model,
)

from core.pydantic import DeleteModel

from apps.user.schemas import (
    UserAddModel,
    UserUpdateModel,
)


from fastapi import APIRouter

router = APIRouter(prefix="")


@router.get(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("view_user"))]
)
async def get_all_users(
    request: Request,
    page_number: int | None = 1,
    page_size: int | None = 20,
    id: int | None = None,
    session=Depends(get_session),
):
    if page_number < 1:
        page_number = 1
    await log_request(request)
    if id:
        user_info = User.from_id(session, id)
        return response_model(data=user_info)
    result, count = User.get_all(
        session=session, page_number=page_number, page_size=page_size
    )
    final_page = ceil(count / page_size)
    next_page, previous_page = None, None
    if page_size * page_number < count:
        next_page = f"/api/v1/user?page_number={page_number+1}&page_size={page_size}"
    if page_number > 1:
        if page_number > final_page:
            previous_page = (
                f"/api/v1/user?page_number={final_page}&page_size={page_size}"
            )
        else:
            previous_page = (
                f"/api/v1/user?page_number={page_number-1}&page_size={page_size}"
            )
    return response_model(
        data={
            "pagination": {
                "total": count,
                "page_number": page_number,
                "page_Size": page_size,
                "next_page": next_page,
                "previous_page": previous_page,
                "final_page": final_page,
            },
            "result": result,
        }
    )


@router.post(
    "/user",
    status_code=201,
    tags=["User"],
    dependencies=[Depends(PermissionChecker("create_user"))],
)
async def add_user(
    data: UserAddModel,
    request: Request,
    backgroundTasks: BackgroundTasks,
    session=Depends(get_session),
):
    await log_request(request)
    email_exist = User.from_email(session, data.email, check=True)
    if not email_exist:
        password, username, response = User.add(
            session, **data.model_dump(exclude_unset=True)
        )
        backgroundTasks.add_task(
            send_mail.welcome_mail,
            email_to_send_to=data.email,
            username=username,
            password=password,
        )
        return response
    raise HTTPException(
        status_code=409,
        detail=response_model(message="Duplicate Value", error="Email already exist"),
    )


@router.patch(
    "/user/{email}",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("update_user"))],
)
async def update_user(
    data: UserUpdateModel,
    request: Request,
    email: EmailStr,
    session=Depends(get_session),
):
    await log_request(request)
    user_to_update = User.from_email(session, email)
    return response_model(
        message=User.update(
            user_to_update, session, **data.model_dump(exclude_unset=True)
        )
    )


@router.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(
    data: DeleteModel,
    request: Request,
    session=Depends(get_session),
):
    await log_request(request)
    user_to_delete = User.from_email(session, data.identifier)
    if user_to_delete.devices:
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.CONFLICT,
                error=constants.DEVICE_ALREADY_IN_USED,
            ),
        )
    return response_model(message=User.delete(session, user_to_delete))


@router.get("/user/me", tags=["User"])
async def my_info(session=Depends(get_session), token=Depends(auth.validate_token)):
    return response_model(data=User.from_email(session, token["user_identifier"]))


@router.get(
    "/user/record",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def user_records(
    email,
    session=Depends(get_session),
):
    user_object = User.from_email(session, email)
    user_id = user_object.id
    return response_model(
        message="Successful",
        data={
            "result": session.scalars(
                Select(DeviceRequestRecord).where(
                    DeviceRequestRecord.user_id == user_id
                )
            ).all()
        },
        # message="Successful", data=DeviceRequestRecord.user_record(session,user_id)
    )


@router.get("/user/current-device", tags=["User"])
async def current_device(
    token: str = Depends(auth.validate_token), session=Depends(get_session)
):
    user = User.from_email(session, token["user_identifier"])
    current_device = user.devices
    if not current_device:
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=f"No device is associated with the {user.full_name}",
            ),
        )
    return response_model(data={"result": current_device})


@router.get(
    "/user/{id}/current-device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_device_by_user_id(id: int, session=Depends(get_session)):
    user = User.from_id(session, id)
    current_devices = user.devices
    if not current_devices:
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.no_device_associated(user.full_name),
            ),
        )
    return response_model(data={"result": current_devices})
