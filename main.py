import datetime
from math import ceil
from fastapi import Depends, FastAPI, Form, HTTPException, Request, BackgroundTasks
from pydantic import EmailStr
from database.database_connection import try_session_commit, session
from models import Device, DeviceRequestRecord, MaintenanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils.logger import logger
from utils import send_mail
from utils.helper_function import (
    check_for_null_or_deleted,
    error_response,
    generate_password,
    log_request,
    normal_response,
)
from utils.schema import (
    ChangePasswordModel,
    DeviceAddModel,
    DeleteModel,
    DeviceMaintenanceModel,
    DeviceRequestModel,
    DeviceReturnFromMaintenanceModel,
    DeviceType,
    DeviceUpdateModel,
    LoginModel,
    RefreshTokenModel,
    ResetPasswordModel,
    UserAddModel,
    UserUpdateModel,
)

description = """
Device Management API helps you maintain your devices and their users. 🚀

"""

app = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All the endpoint have been moved to `/api/v1/docs`. See you there.",
    version="0.0.1",
    root_path="/api",
)

api_v1 = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All your Device related stuff.",
    version="1.0.1",
)


@api_v1.get("/", tags=["Home"])
async def home():
    return "Welcome Home"


@api_v1.post("/password/reset", tags=["Authentication"])
def reset_password(token=Form(), new_password=Form(), confirm_password=Form()):
    email = auth.decode_otp_jwt(token)
    email = email["user_identifier"]
    result = User.reset_password(email, new_password, confirm_password)
    if result:
        return normal_response(message="Your password has been successfully updated.")


@api_v1.post("/user/login", tags=["User"])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@api_v1.post("/user/refresh-token", tags=["User"], status_code=201)
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodeRefreshJWT(refreshToken.token)
    if token:
        return normal_response(data={"access_token": token})
    raise HTTPException(
        status_code=401,
        detail={
            "Error": {
                "error_type": constant_messages.TOKEN_ERROR,
                "error_message": constant_messages.TOKEN_VERIFICATION_FAILED,
            }
        },
    )


@api_v1.post("/password/forget", tags=["Authentication"])
async def forget_password(
    resetPassword: ResetPasswordModel, backgroundTasks: BackgroundTasks
):
    user_object = User.from_email(resetPassword.email)
    if not user_object:
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constant_messages.REQUEST_NOT_FOUND,
                error=constant_messages.request_not_found("user", "email"),
            ),
        )
    password = generate_password(12)
    backgroundTasks.add_task(
        send_mail.reset_mail,
        email_to_send_to=resetPassword.email,
        username=user_object.full_name,
        password=password,
    )
    # user_object.
    user_object.temp_password = auth.hash_password(password)
    user_object.temp_password_created_at = datetime.datetime.now(datetime.UTC)
    try_session_commit(session)
    return normal_response(message="Please check your email for temporary password")


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
                message=constant_messages.REQUEST_NOT_FOUND,
                error=constant_messages.request_not_found(
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


@api_v1.get(
    "/user",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("view_user"))]
)
async def get_all_users(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
    id: int | None = None,
):
    await log_request(request)
    if id:
        user_info = User.from_id(id)
        check_for_null_or_deleted(user_info, "id", "user")
        return normal_response(data=user_info)
    result, count = User.get_all(skip=skip, limit=limit)
    return normal_response(
        data={
            "pagination": {"total": count, "skip": skip, "limit": limit},
            "result": result,
        }
    )


@api_v1.post(
    "/user",
    status_code=201,
    tags=["User"],
    dependencies=[Depends(PermissionChecker("create_user"))],
)
async def add_user(
    userAddModel: UserAddModel, request: Request, backgroundTasks: BackgroundTasks
):
    await log_request(request)
    password, username, response = User.add(**userAddModel.model_dump())
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=userAddModel.email,
        username=username,
        password=password,
    )
    return response


@api_v1.patch(
    "/user/{email}",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("update_user"))],
)
async def update_user(
    userUpdateModel: UserUpdateModel, request: Request, email: EmailStr
):
    await log_request(request)
    return normal_response(message=User.update(email, **userUpdateModel.model_dump()))


@api_v1.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=User.delete(**userDeleteModel.model_dump()))


@api_v1.get("/user/me", tags=["User"])
async def my_info(token=Depends(auth.validate_token)):
    return normal_response(data=User.from_email(token["user_identifier"]))


@api_v1.get("/user/record/", tags=["User"])
async def user_records(email):
    user_object = User.from_email(email)
    check_for_null_or_deleted(user_object)

    user_id = user_object.id

    return normal_response(
        message="Successful", data=DeviceRequestRecord.user_record(user_id)
    )


@api_v1.post("/user/change-password", tags=["User"])
def update_password(
    changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)
):
    return normal_response(
        message=User.change_password(
            email=token.get("user_identifier"), **changePasswordModel.model_dump()
        )
    )


@api_v1.get("/user/current-device", tags=["User"])
async def current_device(token: str = Depends(auth.validate_token)):
    current_device = User.current_device(token)
    return normal_response(data=current_device)


@api_v1.get(
    "/user/{id}/current-device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_devices_user_id(id: int):
    current_devices = User.current_devices_by_user_id(id)
    return current_devices


app.mount("/v1", api_v1)
