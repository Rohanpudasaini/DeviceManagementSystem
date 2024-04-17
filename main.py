from fastapi import Depends, FastAPI, Form, HTTPException, Request, BackgroundTasks
from fastapi.templating import Jinja2Templates
from models import Device, DeviceRequestRecord, MaintainanceHistory, User
from auth import auth
from auth.permission_checker import PermissionChecker
from utils import constant_messages
from utils.logger import logger
from utils import send_mail
from utils.helper_function import check_for_null_or_deleted, error_response, log_request, normal_response
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
templates = Jinja2Templates(directory='templates')

@app.get('/verify_otp')
def verify_otp(token:str, request:Request):
    try:
        token_data = auth.decode_otp_jwt(token)
    except HTTPException:
        return templates.TemplateResponse(
            request=request,
            name='expired.html')
    if token_data:
        return templates.TemplateResponse(
            request=request,
            name = 'test.html',
            context={"token":token}
            )
    
@app.post('/reset_password')
def reset_password(request:Request,token=Form(), new_password=Form(),confirm_password=Form()):
    email = auth.decode_otp_jwt(token)
    email = email['user_identifier']
    result = User.change_password(email,new_password,confirm_password)
    if result:
        return templates.TemplateResponse(
            request = request,
            name ='sucess.html'
        )

@app.get('/', tags=['Home'])
async def home():
    return "Welcome Home"


@app.post('/login', tags=['Authentication'])
async def login(loginModel: LoginModel):
    return User.login(**loginModel.model_dump())


@app.post('/refresh', tags=['Authentication'], status_code=201)
async def get_new_accessToken(refreshToken: RefreshTokenModel):
    token = auth.decodRefreshJWT(refreshToken.token)
    if token:
        return normal_response(data={
            'access_token': token
        })
    raise HTTPException(
        status_code=401,
        detail={
            'Error': {
                'error_type': constant_messages.TOKEN_ERROR,
                'error_message': constant_messages.TOKEN_VERIFICATION_FAILED
            }
        }
    )

@app.post('/forget_password', tags=['Authentication'])
async def forget_password(resetPassword:ResetPasswordModel, backgroundTasks:BackgroundTasks):
    is_user = User.from_email(resetPassword.email)
    if not is_user:
        raise HTTPException(
            status_code=404, 
            detail=error_response(
                error={
                    "error_type": constant_messages.REQUEST_NOT_FOUND,
                    "error_message": constant_messages.request_not_found('user', "email")
                }))
    backgroundTasks.add_task(
        send_mail.reset_mail,
        email_to_send_to=resetPassword.email,
        username=is_user.full_name,
        token = auth.generate_otp_JWT(resetPassword.email))
    return normal_response(message="Please check your email for password reset link")



@app.get('/device', tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def get_all_device(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
    id: int|None = None
):
    await log_request(request)
    if id:
        user_info = Device.from_id(id)
        check_for_null_or_deleted(user_info, 'id', 'user')
        return normal_response(data=user_info)
    result, count = Device.get_all(skip=skip, limit=limit)
    logger.info([singleresult.__dict__ for singleresult in result])
    return normal_response(data=[{
        'total': count,
        'skip': skip,
        'limit': limit
    }, result
    ])


@app.post('/device', tags=['Device'], status_code=201, dependencies=[Depends(PermissionChecker('create_device'))])
async def add_device(deviceAddModel: DeviceAddModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.add(**deviceAddModel.model_dump()))


@app.patch('/device', tags=['Device'], dependencies=[Depends(PermissionChecker('update_device'))])
async def update_device(deviceUpdateModel: DeviceUpdateModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.update(**deviceUpdateModel.model_dump()))


@app.delete('/device', tags=["Device"], dependencies=[Depends(PermissionChecker('delete_device'))])
async def delete_device(deviceDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=Device.delete(**deviceDeleteModel.model_dump()))



@app.get('/device/search',tags=['Device'], dependencies=[Depends(PermissionChecker('view_device'))])
async def search_device(name=None,brand=None):
    search_devices=Device.search_device(name,brand)
    return search_devices


@app.post('/device/request', tags=['Device'], dependencies=[Depends(PermissionChecker('request_device'))])
async def request_device(deviceRequestModel: DeviceRequestModel, request: Request, token=Depends(auth.validate_token)):
    await log_request(request)
    email = token.get('user_identifier')
    return normal_response(message=DeviceRequestRecord.allot_to_user(user_email=email, mac_address=deviceRequestModel.mac_address))


@app.post('/device/return', tags=['Device'], dependencies=[Depends(PermissionChecker('request_device'))])
async def return_device(deviceReturnModel: DeviceRequestModel, request: Request, token=Depends(auth.validate_token)):
    await log_request(request)
    email = token.get('user_identifier')
    return normal_response(message=DeviceRequestRecord.return_device(user_email=email, mac_address=deviceReturnModel.mac_address))


@app.post(
    '/device/request_maintainance',
    tags=['Device'],
    status_code=201,
    dependencies=[Depends(PermissionChecker('request_device'))]
)
async def request_maintainance(
    deviceMaintainanceModel: DeviceMaintainanceModel,
    token=Depends(auth.validate_token)
):
    return normal_response(message=MaintainanceHistory.add(
        email=token.get('user_identifier'),
        **deviceMaintainanceModel.model_dump()
    ))


@app.patch(
    '/device/return_maintainance',
    tags=['Device'],
    dependencies=[Depends(PermissionChecker('request_device'))]
)
async def return_maintainance(deviceReturn: DeviceReturnFromMaintainanceModel):
    return normal_response(message=MaintainanceHistory.update(**deviceReturn.model_dump()))


@app.get('/user', tags=['User'], dependencies=[Depends(PermissionChecker('view_user'))])
async def get_all_users(
    request: Request,
    skip: int | None = 0,
    limit: int | None = 20,
    id: int | None = None
):
    await log_request(request)
    if id:
        user_info = User.from_id(id)
        check_for_null_or_deleted(user_info, 'id', 'user')
        return normal_response(data=user_info)
    result, count = User.get_all(skip=skip, limit=limit)
    return normal_response(data=[{
        'total': count,
        'skip': skip,
        'limit': limit
    }, result])
    

@app.post(
    '/user',
    status_code=201,
    tags=['User'],
    dependencies=[Depends(PermissionChecker('create_user'))]
)
async def add_user(
    userAddModel: UserAddModel,
    request: Request
):
    await log_request(request)
    return User.add(**userAddModel.model_dump())


@app.patch('/user', tags=['User'], dependencies=[Depends(PermissionChecker('update_user'))])
async def update_user(userUpdateModel: UserUpdateModel, request: Request):
    await log_request(request)
    return normal_response(message=User.update(**userUpdateModel.model_dump()))


@app.delete('/user', tags=["User"], dependencies=[Depends(PermissionChecker('delete_user'))])
async def delete_user(userDeleteModel: DeleteModel, request: Request):
    await log_request(request)
    return normal_response(message=User.delete(**userDeleteModel.model_dump()))


@app.get('/user/me', tags=["User"])
async def my_info(token = Depends(auth.validate_token)):
    return normal_response(data=User.from_email(token['user_identifier']))


@app.post('/user/request_mail', tags=['User'])
def request_mail(backgroundTasks: BackgroundTasks, token=Depends(auth.validate_token)):
    email = token['user_identifier']
    user_object = User.from_email(email)
    backgroundTasks.add_task(
        send_mail.welcome_mail,
        email_to_send_to=email,
        username=user_object.full_name,
        password=user_object.password)
    return normal_response(message="Mail sent sucessfully, please check your registered mail")


@app.post('/user/change_password', tags=['User'])
def update_password(changePasswordModel: ChangePasswordModel, token=Depends(auth.validate_token)):
    return normal_response(message=User.change_default_password(email=token.get("user_identifier"), **changePasswordModel.model_dump()))


@app.get("/user/current_device", tags=['User'])
async def current_device(token: str = Depends(auth.validate_token)):
    current_device = User.current_device(token)
    return normal_response(data=current_device)


@app.get("/user/{id}/current_device",tags=['User'], dependencies=[Depends(PermissionChecker('all_access'))])
async def current_devices_user_id(id):
    current_devices=User.current_devices_by_user_id(id)
    return current_devices