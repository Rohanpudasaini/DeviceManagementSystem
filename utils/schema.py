from enum import Enum
from pydantic import BaseModel, ConfigDict, EmailStr
import datetime


class Designation(Enum):
    USER='user'
    ADMIN='admin'
    OPERATOR='operator'
    TECHNICIAN='technician'
    AUDITOR='auditor'
    
class DeviceType(Enum):
    LAPTOP='laptop'
    ANDROID='android'
    CAMERA='camera'
    PRINTER='printer'
    SCANNER='scanner'
    PHONE='phone'
    TABLET= 'tablet'
    CONSOLE= 'console'
    EREADER= 'ereader'
    WEARABLE= 'wearable'
    DRONE= 'drone'
    SMART_HOME_DEVICE= 'smart home device'
    DESKTOP= 'desktop'
    
    
class DeviceStatus(Enum):
    PUBLISHED='published'
    SCHEDULED='scheduled'
    DRAFT='draft'
    ADDED='added'
    
class RefreshTokenModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token:str


class UserAddModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email:EmailStr
    first_name:str
    last_name:str
    phone_no:str|None = None
    address:str|None = None
    city:str|None = None
    postal_code:str|None=None
    designation:Designation = Designation.USER
    profile_pic_url:str|None = None
    role:list[str] = None

class DeviceAddModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name:str
    brand:str
    price:float
    description:str
    status:DeviceStatus = DeviceStatus.ADDED
    bill_image:str
    product_images:list[str]|None=None
    type:DeviceType = DeviceType.LAPTOP
    specification:dict|None = None
    purchase_date:datetime.datetime = datetime.datetime.now(datetime.UTC).date()

class DeviceRequestModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device_id:int
    
class DeviceMaintainanceModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    description:str
    cost:float|None =None
    device_id:int
    maintainance_requested_user_id:int
    current_device_owner_id:int
    sent_for_repair:datetime.datetime = datetime.datetime.now(datetime.UTC).date()


class DeviceUpdateModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id:int
    name:str|None = None
    brand:str|None = None
    price:float|None = None
    description:str|None = None
    status:DeviceStatus|None = None
    product_images:list[str]|None=None
    specification:dict|None = None


class UserUpdateModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id:int
    email:EmailStr|None = None
    first_name:str|None = None
    last_name:str|None = None
    phone_no:str|None = None
    address:str|None = None
    city:str|None = None
    postal_code:str|None = None
    allow_notification:bool|None = None
    designation:Designation|None = None
    profile_pic_url:str|None = None
    role:list[str]|None = None

class DeleteModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id_to_delete:int
    
class LoginModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email:EmailStr
    password:str
    
class ChangePasswordModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    old_password:str
    new_password:str