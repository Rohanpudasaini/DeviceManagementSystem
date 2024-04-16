from fastapi import Depends, FastAPI, HTTPException, Request, BackgroundTasks
from models import Device, DeviceRequestRecord, MaintainanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils.logger import logger
from utils import send_mail
import os
from utils.helper_function import check_for_null_or_deleted, log_request, response
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


@app.get('/', tags=['Home'])
async def home():
    return "Welcome Home"


@app.post('/login', tags=['Authentication'])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@app.post(
    '/add_user',
    status_code= 201,
    tags=['Authentication'],
    dependencies=[Depends(PermissionChecker('create_user'))]
    )
async def add_user(
    userAddModel: UserAddModel,
    request: Request
    ):
    await log_request(request)
    return User.add(**userAddModel.model_dump())


@app.post('/refresh', tags=['Authentication'],status_code= 201)
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
    
    #latest update code  
@app.get("/user/current_device",tags=['Device'])
async def current_device(token:str=Depends(auth.validate_token)):
    current_device=User.current_device(token)
    return current_device
    


@app.get('/devices', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def get_all_device(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
):
    await log_request(request)
    result, count = Device.get_all(skip=skip, limit=limit)
    logger.info([singleresult.__dict__ for singleresult in result])
    return result, {'total': count,
                    'skip':skip,
                    'limit':limit
                    }


@app.post('/devices', tags=['Device'], status_code= 201, dependencies=[Depends(PermissionChecker('create_device'))])
async def add_device(deviceAddModel: DeviceAddModel, request: Request):
    await log_request(request)
    return Device.add(**deviceAddModel.model_dump())


@app.patch('/devices', tags=['Device'], dependencies=[Depends(PermissionChecker('update_device'))])
async def update_device(deviceUpdateModel: DeviceUpdateModel, request: Request):
    await log_request(request)
    return Device.update(**deviceUpdateModel.model_dump())


@app.delete('/device', tags=["Device"], dependencies=[Depends(PermissionChecker('delete_device'))])
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return Device.delete(**deviceDeleteModel.model_dump())


@app.get('/devices/', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def search_device(request: Request, name=None, brand=None):
    await log_request(request)
    if not name and not brand:
        return "Please provide Search Query"
    return Device.search(name, brand)


# @app.get('/device/{id}', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
# async def get_single_device(id: int, request: Request):
#     await log_request(request)
#     device_info = Device.from_id(id)
#     check_for_null_or_deleted(device_info)
#     if device_info:
#         logger.info(device_info.__dict__)
#     else:
#         logger.warning(f"No device with id {id}")
#     return device_info


@app.post('/request', tags=['Device'], dependencies=[Depends(PermissionChecker('request_device'))])
async def request_device(deviceRequestModel: DeviceRequestModel, request: Request, token=Depends(auth.validate_token)):
    await log_request(request)
    email = token.get('user_identifier')
    return DeviceRequestRecord.allot_to_user(user_email=email, mac_address=deviceRequestModel.mac_address)


@app.post('/return', tags=['Device'], dependencies=[Depends(PermissionChecker('request_device'))])
async def return_device(deviceReturnModel: DeviceRequestModel, request: Request, token=Depends(auth.validate_token)):
    await log_request(request)
    email = token.get('user_identifier')
    return DeviceRequestRecord.return_device(user_email=email, mac_address=deviceReturnModel.mac_address)


@app.post(
    '/device/request_maintainance',
    tags=['Device'],
    status_code= 201,
    dependencies=[Depends(PermissionChecker('request_device'))]
    )
async def request_maintainance(
    deviceMaintainanceModel: DeviceMaintainanceModel,
    token = Depends(auth.validate_token)
    ):
    return MaintainanceHistory.add(
        email= token.get('user_identifier'),
        **deviceMaintainanceModel.model_dump()
        )


@app.patch(
    '/device/return_maintainance',
    tags=['Device'],
    dependencies=[Depends(PermissionChecker('request_device'))]
    )
async def return_maintainance(deviceReturn:DeviceReturnFromMaintainanceModel):
    return MaintainanceHistory.update(**deviceReturn.model_dump())

@app.get('/users', tags=['User'], dependencies=[Depends(PermissionChecker('view_user'))])
async def get_all_users(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
    id: int | None = None
):
    await log_request(request)
    if id:
        user_info =  User.from_id(id)
        check_for_null_or_deleted(user_info,'id','user')
        return response(data=user_info)
    result, count = User.get_all(skip=skip, limit=limit)
    return response(data =[{
        'total': count,
        'skip': skip,
        'limit': limit
    }, result])


@app.patch('/users', tags=['User'], dependencies=[Depends(PermissionChecker('update_user'))])
async def update_user(userUpdateModel: UserUpdateModel, request: Request):
    await log_request(request)
    return User.update(**userUpdateModel.model_dump())


@app.delete('/user', tags=["User"], dependencies=[Depends(PermissionChecker('delete_user'))])
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return User.delete(**userDeleteModel.model_dump())


@app.post('/user/request_mail', tags=['User'])
def request_mail(backgroundTasks:BackgroundTasks,token = Depends(auth.validate_token)):
    email = token['user_identifier']
    user_object = User.from_email(email)
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=email,
        username=user_object.full_name,
        password=user_object.password)
    return response(message="Mail sent sucessfully, please check your registered mail")


@app.post('/user/change_password', tags=['Authentication'])
def update_password(changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)):
    return User.change_default_password(email=token.get("user_identifier"), **changePasswordModel.model_dump())



