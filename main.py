from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Request, BackgroundTasks
from models import Device, DeviceRequestRecord, MaintainanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils import send_mail
from utils.helper_function import check_for_null_or_deleted, log_request
from utils.schema import (
    ChangePasswordModel,
    DeviceAddModel,
    DeleteModel,
    DeviceMaintainanceModel,
    DeviceRequestModel,
    DeviceUpdateModel,
    LoginModel,
    RefreshTokenModel,
    UserAddModel,
    UserUpdateModel
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
)


@app.get('/')
async def home():
    return "Welcome Home"


@app.post('/login', tags=['Authentication'])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@app.post('/signup', tags=['Authentication'])
async def add_user(userAddModel: UserAddModel, request: Request, backgroundTasks: BackgroundTasks):
    await log_request(request)
    username, email, password, message = User.add(**userAddModel.model_dump())
    backgroundTasks.add_task(
        send_mail.welcome_mail, email_to_send_to=email, username=username, password=password)
    return message


@app.post('/change_password', tags=['Authentication'])
def change_password(loginModel: LoginModel):
    # print(loginModel)
    access_token, _ = auth.generate_JWT(email=loginModel.email)
    return {
        'Redirect': 'You are redirectd as you are using the default password',
        "Redirect_message": "Please Send Patch method to '/change_password' with new password and your token in header.",
        'access_token': access_token
    }


@app.patch('/change_password', tags=['Authentication'])
def update_password(changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)):
    return User.change_password(email=token.get("user_identifier"), **changePasswordModel.model_dump())


@app.post('/refresh', tags=['Authentication'])
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodRefreshJWT(refreshToken.token)
    if token:
        return {
            'access_token': token
        }
    raise HTTPException(
        status_code=401,
        detail={
            'Error': {
                'error_type': constant_messages.TOKEN_ERROR,
                'error_message': constant_messages.TOKEN_VERIFICATION_FAILED
            }
        }
    )


@app.get('/devices', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def get_all_device(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
):
    await log_request(request)
    return Device.get_all(skip=skip, limit=limit)


@app.get('/test')
def test(token: Annotated[dict, Depends(PermissionChecker('view_device'))]):
    return token


@app.post('/devices', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def add_device(deviceAddModel: DeviceAddModel, request: Request):
    await log_request(request)
    return Device.add(**deviceAddModel.model_dump())


@app.patch('/devices', tags=['Device'])
async def update_device(deviceUpdateModel: DeviceUpdateModel, request: Request):
    await log_request(request)
    return Device.update(**deviceUpdateModel.model_dump())


@app.delete('/device', tags=["Device"])
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return Device.delete(**deviceDeleteModel.model_dump())


@app.get('/devices/', tags=['Device'])
async def search_device(request: Request, name=None, brand=None):
    await log_request(request)
    if not name and not brand:
        return "Please provide Search Query"
    return Device.search(name, brand)


@app.get('/device/{id}', tags=['Device'])
async def get_single_user(id: int, request: Request):
    await log_request(request)
    device_info = Device.from_id(id)
    check_for_null_or_deleted(device_info)
    return device_info


@app.post('/request', tags=['Device'])
async def request_device(deviceRequestModel: DeviceRequestModel, request: Request):
    await log_request(request)
    return DeviceRequestRecord.allot_to_user(**deviceRequestModel.model_dump())


@app.post('/return', tags=['Device'])
async def return_device(deviceReturnModel: DeviceRequestModel, request: Request):
    await log_request(request)
    return DeviceRequestRecord.return_device(**deviceReturnModel.model_dump())


@app.post('/maintainance', tags=['Device'])
async def request_maintainance(deviceMaintainanceModel: DeviceMaintainanceModel):
    return MaintainanceHistory.add(**deviceMaintainanceModel.model_dump())


@app.get('/users', tags=['User'])
async def get_all_users(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20
):
    await log_request(request)
    return User.get_all(skip=skip, limit=limit)


@app.patch('/users', tags=['User'])
async def update_user(userUpdateModel: UserUpdateModel, request: Request):
    await log_request(request)
    return User.update(**userUpdateModel.model_dump())


@app.delete('/user', tags=["User"])
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return User.delete(**userDeleteModel.model_dump())


@app.get('/user/{id}', tags=['User'])
async def get_single_user(id: int, request: Request):
    await log_request(request)
    user_info = User.from_id(id)
    check_for_null_or_deleted(user_info)
    return user_info
