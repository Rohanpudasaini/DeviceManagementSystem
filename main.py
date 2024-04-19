import datetime
from fastapi import Depends, FastAPI, Form, HTTPException, Request, BackgroundTasks
from database.database_connection import try_session_commit, session
from models import Device, DeviceRequestRecord, MaintainanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils.logger import logger
from utils import send_mail
import os
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
    DeviceMaintainanceModel,
    DeviceRequestModel,
    DeviceReturnFromMaintainanceModel,
    DeviceUpdateModel,
    LoginModel,
    RefreshTokenModel,
    ResetPasswordModel,
    UserAddModel,
    UserUpdateModel,
)


description = """
Device Management API helps you maintain your devices and their users. 🚀

Please go to  `/` to know about ervery availabe route.
"""

app = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All your Device related stuff.",
    version="0.0.1",
    contact={
        "name": "Rohan Pudasaini",
        "url": "https://rohanpudasaini.com.np",
        "email": "admin@rohanpudasaini.com.np",
    },
    root_path="/api",
)

api_v1 = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All your Device related stuff.",
    version="1.0.1",
    contact={
        "name": "Rohan Pudasaini",
        "url": "https://rohanpudasaini.com.np",
        "email": "admin@rohanpudasaini.com.np",
    }
)


@api_v1.get("/", tags=["Home"])
async def home():
    return "Welcome Home"


@api_v1.post("/reset_password", tags=["Authentication"])
def reset_password(
    token=Form(), new_password=Form(), confirm_password=Form()
):
    email = auth.decode_otp_jwt(token)
    email = email["user_identifier"]
    result = User.reset_password(email, new_password, confirm_password)
    if result:
        return normal_response(message="Your password has been successfully updated.")


@api_v1.post("/user/login", tags=["Authentication"])
async def login(loginModel: LoginModel,backgroundTasks: BackgroundTasks):
    return User.login(**loginModel.model_dump())



@api_v1.post("/user/request_mail", tags=["User"])
def request_mail(backgroundTasks: BackgroundTasks, token=Depends(auth.validate_token)):
    email = token["user_identifier"]
    user_object = User.from_email(email)
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=email,
        username=user_object.full_name,
        password=user_object.password,
    )
    return normal_response(
        message="Mail sent sucessfully, please check your registered mail"
    )


@api_v1.post("/user/refresh_token", tags=["Authentication"], status_code=201)
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodRefreshJWT(refreshToken.token)
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


@api_v1.post("/forget_password", tags=["Authentication"])
async def forget_password(
    resetPassword: ResetPasswordModel, backgroundTasks: BackgroundTasks
):
    user_object = User.from_email(resetPassword.email)
    if not user_object:
        raise HTTPException(
            status_code=404,
            detail=error_response(
                error={
                    "error_type": constant_messages.REQUEST_NOT_FOUND,
                    "error_message": constant_messages.request_not_found(
                        "user", "email"
                    ),
                }
            ),
        )
    password = generate_password(12)
    backgroundTasks.add_task(
        send_mail.reset_mail,
        email_to_send_to=resetPassword.email,
        username=user_object.full_name,
        password = password,
    )
    # user_object.
    user_object.temp_password = auth.hash_password(password)
    user_object.temp_password_created_at = datetime.datetime.now(datetime.UTC)
    try_session_commit(session)
    return normal_response(message="Please check your email for temporary password")


@api_v1.get(
    "/device", tags=["Device"], dependencies=[Depends(PermissionChecker("view_device"))]
)
async def get_all_device(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
    id: int | None = None,
):
    await log_request(request)
    if id:
        user_info = Device.from_id(id)
        check_for_null_or_deleted(user_info, "id", "user")
        return normal_response(data=user_info)
    result, count = Device.get_all(skip=skip, limit=limit)
    logger.info([singleresult.__dict__ for singleresult in result])
    return normal_response(
        data={
            "pagination":
                {
                    "total": count, 
                    "skip": skip, 
                    "limit": limit
                    }, 
            'result':result}
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
    "/device",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("update_device"))],
)
async def update_device(deviceUpdateModel: DeviceUpdateModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.update(**deviceUpdateModel.model_dump()))


@api_v1.delete(
    "/device",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("delete_device"))],
)
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.delete(**deviceDeleteModel.model_dump()))


@api_v1.get(
    "/device/search",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("view_device"))],
)
async def search_device(name=None, brand=None):
    search_devices = Device.search_device(name, brand)
    return search_devices


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
    "/device/request_maintainance",
    tags=["Device"],
    status_code=201,
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def request_maintainance(
    deviceMaintainanceModel: DeviceMaintainanceModel, token=Depends(auth.validate_token)
):
    return normal_response(
        message=MaintainanceHistory.add(
            email=token.get("user_identifier"), **deviceMaintainanceModel.model_dump()
        )
    )


@api_v1.patch(
    "/device/return_maintainance",
    tags=["Device"],
    dependencies=[Depends(PermissionChecker("request_device"))],
)
async def return_maintainance(deviceReturn: DeviceReturnFromMaintainanceModel):
    return normal_response(
        message=MaintainanceHistory.update(**deviceReturn.model_dump())
    )


@api_v1.get(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("view_user"))]
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
            "pagination":
                {
                    "total": count, 
                    "skip": skip, 
                    "limit": limit
                    }, 
            "result":result
            }
    )


@api_v1.post(
    "/user",
    status_code=201,
    tags=["User"],
    dependencies=[Depends(PermissionChecker("create_user"))],
)
async def add_user(userAddModel: UserAddModel, request: Request, backgroundTasks:BackgroundTasks):
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
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("update_user"))]
)
async def update_user(userUpdateModel: UserUpdateModel, request: Request):
    await log_request(request)
    return normal_response(message=User.update(**userUpdateModel.model_dump()))


@api_v1.delete(
    "/user", tags=["User"], dependencies=[Depends(PermissionChecker("delete_user"))]
)
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=User.delete(**userDeleteModel.model_dump()))


@api_v1.get("/user/me", tags=["User"])
async def my_info(token=Depends(auth.validate_token)):
    return normal_response(data=User.from_email(token["user_identifier"]))



@api_v1.post("/user/change_password", tags=["User"])
def update_password(
    changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)
):
    return normal_response(
        message=User.change_password(
            email=token.get("user_identifier"), **changePasswordModel.model_dump()
        )
    )


@api_v1.get("/user/current_device", tags=["User"])
async def current_device(token: str = Depends(auth.validate_token)):
    current_device = User.current_device(token)
    return normal_response(data=current_device)


@api_v1.get(
    "/user/{id}/current_device",
    tags=["User"],
    dependencies=[Depends(PermissionChecker("all_access"))],
)
async def current_devices_user_id(id):
    current_devices = User.current_devices_by_user_id(id)
    return current_devices


app.mount("/v1", api_v1)
