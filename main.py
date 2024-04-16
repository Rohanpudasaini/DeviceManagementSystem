from fastapi import Depends, FastAPI, HTTPException, Request, BackgroundTasks
from models import Device, DeviceRequestRecord, MaintainanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils.logger import logger
from utils import send_mail
import os
from utils.helper_function import check_for_null_or_deleted, log_request
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
    request: Request,
    backgroundTasks: BackgroundTasks
    ):
    await log_request(request)
    username, email, password, message = User.add(**userAddModel.model_dump())
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=email,
        username=username,
        password=password)
    return message


@app.post('/change_password', tags=['Authentication'])
def change_password(loginModel: LoginModel):
    # print(loginModel)
    is_valid, _ = User.verify_credential(**loginModel.model_dump())
    if is_valid:
        access_token, _ = auth.generate_JWT(email=loginModel.email)
        return {
            'Redirect': 'You are redirectd as you are using the default password',
            "Redirect_message": "Please Send Patch method to '/change_password' with new password and your token in header.",
            'access_token': access_token
        }
    raise HTTPException(
        status_code=401,
        detail={
            'error_type': "Authenticatin failed",
            'error_message': "Please provide valid credentials"
        }
    )


@app.patch('/change_password', tags=['Authentication'])
def update_password(changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)):
    return User.change_password(email=token.get("user_identifier"), **changePasswordModel.model_dump())


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
    limit: int | None = 20
):
    await log_request(request)
    result, count = User.get_all(skip=skip, limit=limit)
    return result, {
        'total': count,
        'skip': skip,
        'limit': limit
        
    }


@app.patch('/users', tags=['User'], dependencies=[Depends(PermissionChecker('update_user'))])
async def update_user(userUpdateModel: UserUpdateModel, request: Request):
    await log_request(request)
    return User.update(**userUpdateModel.model_dump())


@app.delete('/user', tags=["User"], dependencies=[Depends(PermissionChecker('delete_user'))])
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return User.delete(**userDeleteModel.model_dump())


@app.get('/user/id/{id}', tags=['User'], dependencies=[Depends(PermissionChecker('view_user'))])
async def get_single_user_from_id(id: int, request: Request):
    await log_request(request)
    user_info = User.from_id(id)
    print(user_info)
    check_for_null_or_deleted(user_info)
    return user_info

@app.get('/user/{email}', tags=['User'], dependencies=[Depends(PermissionChecker('view_user'))])
async def get_single_user_from_email(email: str, request: Request):
    await log_request(request)
    user_info = User.from_email(email)
    check_for_null_or_deleted(user_info)
    return user_info

