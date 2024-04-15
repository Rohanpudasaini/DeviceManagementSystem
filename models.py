from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import DateTime, ForeignKey, Integer, ARRAY, String, Select, Update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_json import mutable_json_type
from utils.helper_function import check_for_null_or_deleted, generate_password
from utils.schema import Designation, DeviceStatus, DeviceType
import datetime
from database.database_connection import session, try_session_commit
from auth import auth
from utils import constant_messages
from utils.logger import logger


class Base(DeclarativeBase):
    pass


class MaintainanceHistory(Base):
    __tablename__ = 'maintainance_history'
    id: Mapped[int] = mapped_column(primary_key=True)
    description: Mapped[str]
    cost: Mapped[int] = mapped_column(nullable=True)
    device_id: Mapped[int] = mapped_column(ForeignKey('device.id'))
    devices = relationship('Device', back_populates='maintainance_record')
    maintainance_requested_user_id: Mapped[int] = mapped_column(
        ForeignKey('user.id'), nullable=True)
    current_device_owner_id: Mapped[int] = mapped_column(
        ForeignKey('user.id'), nullable=True)
    repair_requested = relationship('User', foreign_keys=[
                                    maintainance_requested_user_id], backref='sent_for_repair')
    reported_by = relationship('User', foreign_keys=[
                               current_device_owner_id], backref='reported_device')
    sent_for_repair = mapped_column(DateTime)
    returned_from_repair = mapped_column(DateTime)

    @classmethod
    def add(cls, **kwargs):
        requested_by_user_id = kwargs['maintainance_requested_user_id']
        kwargs.pop('maintainance_requested_user_id')
        current_user_id = kwargs['current_device_owner_id']
        kwargs.pop('current_device_owner_id')
        device_to_repair_id = kwargs['device_id']
        kwargs.pop('device_id')
        device_to_repair = Device.from_id(device_to_repair_id)
        requested_by = User.from_id(requested_by_user_id)
        current_owner = User.from_id(current_user_id)
        if not requested_by and current_owner and device_to_repair:
            logger.error(f'Can\'t find user with id {requested_by_user_id} or {current_user_id} or the device with id {device_to_repair_id} found')
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found('users and device', 'user id and device id')
                    }
                }
            )
        kwargs['devices'] = device_to_repair
        kwargs['repair_requested'] = requested_by
        kwargs['reported_by'] = current_owner

        object_to_add = cls(**kwargs)
        session.add(object_to_add)
        try_session_commit(session)
        device_to_repair.available = False
        session.add(device_to_repair)
        try_session_commit(session)
        logger.info("Sucessfully given device with id {device_to_repair_id} to repair")
        return 'Sucessfully Given For Repair'


class User(Base):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False, deferred=True)
    first_name: Mapped[str]
    last_name: Mapped[str]
    phone_no: Mapped[str]
    address: Mapped[str]
    city: Mapped[str]
    postal_code: Mapped[str]
    profile_pic_url:Mapped[str] = mapped_column(nullable=True)
    creation_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC))
    allow_notification: Mapped[bool] = mapped_column(default=True)
    designation: Mapped[Designation] = mapped_column(default=Designation.USER)
    deleted:Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime ,nullable=True)
    role_id = relationship('Role', back_populates='user_id',
                           secondary='users_roles', lazy='dynamic')
    default_password: Mapped[bool] = mapped_column(default=True)
    devices = relationship("Device", back_populates='user')


    @hybrid_property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @classmethod
    def add(cls, **kwargs):
        # username, email, password, message
        password = generate_password(12)
        kwargs['password'] = auth.hash_password(password)
        user_to_add = cls(**kwargs)
        final_role = []
        if kwargs.get('role'):
            for role_given in kwargs.get('role'):
                role = Role.from_name(role_given)
                final_role.append(role)
        else:
            role = Role.from_name('Viewer')
        if not final_role:
            role = Role.from_name('Viewer')
        user_to_add.roll_id = [role]
        session.add(user_to_add)
        try_session_commit(session)
        logger.info(msg=f'User with username {user_to_add.full_name} Added Sucesully')
        return user_to_add.full_name, user_to_add.email, password ,'User Added Sucesully, please login using the password provided in your mail'

    @classmethod
    def change_password(cls,email,**kwargs):
        user_to_update = cls.from_email(email)
        if auth.verify_password(kwargs['new_password'], user_to_update.password):
            logger.warning("Same password as old password")
            raise HTTPException(
                status_code= 409,
                detail={
                    'error_type': 'Same Password',
                    'error_message': 'New password can\'t be same as the old password'
                }
            )
        if auth.verify_password(kwargs['old_password'], user_to_update.password):
            user_to_update.password = auth.hash_password(kwargs['new_password'])
            user_to_update.default_password = False
            session.add(user_to_update)
            try_session_commit(session)
            logger.info('Password Changed Sucesfully')
            return "Password Changed Sucesfully, Enjoy your account"

    @classmethod
    def update(cls,**kwargs):
        user_to_update = cls.from_id(kwargs['id'])
        kwargs.pop('id')
        if user_to_update.deleted:
            logger.error(msg=f'{user_to_update.name} user is Already Deleted')
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.DELETED_ERROR,
                        'error_message': constant_messages.DELETED_ERROR_MESSAGE
                    }
                }
            )
        print(kwargs)
        for key, value in kwargs.items():
            if value != None:
                # print(value)
                setattr(user_to_update,key,value)
        session.add(user_to_update)
        try_session_commit(session)
        logger.info(msg=f'{user_to_update.name} updated Sucessful')
        return 'Update Sucessful'

    @classmethod
    def delete(cls, **args):
        user_to_delete = cls.from_id(args['id_to_delete'])
        user_to_delete.deleted = True
        user_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(user_to_delete)
        try_session_commit(session)
        logger.info(msg=f'{user_to_delete.name} deleted Sucessfully')
        return "Deleted Sucessfully"

    @classmethod
    def get_all(cls, skip, limit):
        statement = Select(cls).where(cls.deleted==False).offset(skip).limit(limit)
        return session.scalars(statement).all()

    @classmethod
    def from_id(cls, id):
        return session.scalar(Select(cls).where(cls.id == id))
    
    @classmethod
    def from_email(cls, email):
        return session.scalar(Select(cls).where(cls.email == email))

    @classmethod
    def login(cls, **kwargs):
        is_valid, user_object = cls.verify_credential(**kwargs)
        if is_valid:
            access_token, refresh_token = auth.generate_JWT(email=user_object.email)
            if not user_object.default_password:
                logger.info("Login Sucessfull")
                return{
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'fullname': user_object.full_name,
                    'profile_pic_url': user_object.profile_pic_url,
                    'role': user_object.role_id.all()
                }
            kwargs['token'] = access_token
            logger.warning("Default password, redirection to change password")
            return RedirectResponse('/change_password')
        logger.error("Invalid Credentials")
        raise HTTPException(
            status_code=401,
            detail= 'Invalid Credentials'
        )
        
    @classmethod
    def verify_credential(cls, **kwargs):
        user_object = cls.from_email(kwargs['email'])
        check_for_null_or_deleted(user_object, 'email', 'User')
        is_valid = auth.verify_password(kwargs['password'], user_object.password)
        return is_valid, user_object

    @classmethod
    def get_all_role(cls, email):
        user_object = cls.from_email(email)
        return user_object.role_id.all()


class DeviceRequestRecord(Base):
    __tablename__ = 'device_request_records'
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    borrowed_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC))
    returned_date = mapped_column(DateTime, nullable=True, default=None)
    expected_return_date = mapped_column(
        DateTime)
    device_id: Mapped[int] = mapped_column(ForeignKey('device.id'), nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), nullable=True)
    device = relationship('Device', backref='record',
                          foreign_keys=[device_id])
    user = relationship('User', backref='record',
                        foreign_keys=[user_id])

    @hybrid_property
    def is_returned(self):
        if self.returned_date:
            return True
        return False
    
    @classmethod
    def allot_to_user(cls, user_email, device_id):
        logger.info(f"Trying to allot a device with device id {device_id} to user with userid {user_id}")
        device_to_allot = Device.from_id(device_id)
        if not device_to_allot:
            logger.error(f"Can't find the device with deviceid {device_id}")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found('device', 'device id')
                    }
                }
            )
        requested_user = User.from_email(user_email)
        if not requested_user:
            logger.error(f"Can't find the user with email {user_email}")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found('user', 'user id')
                    }
                }
            )
        if not device_to_allot.deleted:
            if device_to_allot.available:
                if device_to_allot.status.value != 'added':
                    logger.error("The device with device id {device_id} is not published")
                    raise HTTPException(
                        status_code=404,
                        detail={
                            'error': {
                                'error_type': constant_messages.REQUEST_NOT_FOUND,
                                'error_message': constant_messages.request_not_found('device', 'device id')
                            }
                        }
                    )
                device_to_allot.user = requested_user
                session.add(device_to_allot)
                try_session_commit(session)
                device_to_allot.available = False
                add_record = cls(
                    expected_return_date=datetime.datetime.now(
                        tz=datetime.UTC) + datetime.timedelta(days=30),
                    device=device_to_allot,
                    user=requested_user
                )
                session.add(add_record)
                try_session_commit(session)
                logger.info("Allocation sucessfull")
                return "sucessfully alloted device"
            logger.error("The device is no longer available")
            raise HTTPException(
                status_code=409,
                detail={
                    'error': {
                        'error_type': constant_messages.INSUFFICIENT_RESOURCES,
                        'error_message': constant_messages.insufficient_resources('device')
                    }
                }
            )
        logger.error("Device is already deleted")
        raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.DELETED_ERROR,
                        'error_message': constant_messages.DELETED_ERROR_MESSAGE
                    }
                }
            )

    @classmethod
    def return_device(cls, user_id, device_id):
        logger.info(f"Trying to return device with id {device_id} by user with id {user_id}")
        device_to_return = Device.from_id(device_id)
        if not device_to_return:
            logger.error("Device not found")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found('device', 'device id')
                    }
                }
            )
        returned_user = User.from_id(user_id)
        if not returned_user:
            logger.error("User not found")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found('user', 'user id')
                    }
                }
            )
        device_to_return.user = None
        device_to_return.available=True
        session.add(device_to_return)
        try_session_commit(session)
        record_to_update = session.scalar(Select(cls).where(cls.device_id==device_id,cls.user_id==user_id, cls.returned_date == None))
        if record_to_update:
            record_to_update.returned_date= datetime.datetime.now(tz=datetime.UTC)
            session.add(record_to_update)
            try_session_commit(session)
            logger.info("Device Returned Sucessfully")
            return 'Device Returned Sucessfully'
        logger.error("The user have already returned the device")
        raise HTTPException(
            status_code=404,
            detail={
                'error': {
                    'error_type': constant_messages.REQUEST_NOT_FOUND,
                    'error_message': constant_messages.request_not_found('Request Record', 'user id or device id or is already returned')
                }
            }
        )


class Device(Base):
    __tablename__ = 'device'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False)
    brand: Mapped[str] = mapped_column(nullable=False)
    price: Mapped[float] = mapped_column(nullable=False)
    description: Mapped[str]
    available: Mapped[bool] = mapped_column(default=True)
    status: Mapped[DeviceStatus] = mapped_column(default=DeviceStatus.ADDED)
    bill_image: Mapped[str]
    product_images = mapped_column(ARRAY(String))
    purchase_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC))
    type: Mapped[DeviceType]
    deleted:Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime ,nullable=True)
    specification = mapped_column(mutable_json_type(dbtype=JSONB, nested=True))
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), nullable=True)
    user = relationship('User', back_populates='devices')
    maintainance_record = relationship(
        'MaintainanceHistory', back_populates='devices')
    # record = relationship('DeviceRequestRecord', back_populates='device')

    @classmethod
    def add(cls, **kwargs):
        device_to_add = cls(**kwargs)
        session.add(device_to_add)
        try_session_commit(session)
        logger.info("Device Added Sucesfully")
        return "Device Added Sucesfully"


    @classmethod
    def update(cls,**kwargs):
        device_to_update = cls.from_id(kwargs['id'])
        kwargs.pop('id')
        if device_to_update.deleted:
            logger.error("The device is already deleted")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.DELETED_ERROR,
                        'error_message': constant_messages.DELETED_ERROR_MESSAGE
                    }
                }
            )
        for key, value in kwargs.items():
            if value:
                setattr(device_to_update,key,value)
        session.add(device_to_update)
        try_session_commit(session)
        logger.info("Update sucessfull")
        return 'Update Sucessful'

    @classmethod
    def delete(cls, **args):
        device_to_delete = cls.from_id(args['id_to_delete'])
        device_to_delete.deleted = True
        device_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(device_to_delete)
        try_session_commit(session)
        logger.info("Deleted Sucessfully")
        return "Deleted Sucessfully"

    @classmethod
    def from_id(cls, id):
        return session.scalar(Select(cls).where(cls.id == id))

    @classmethod
    def get_all(cls, skip, limit):
        statement = Select(cls).where(cls.available==True, cls.deleted==False).offset(skip).limit(limit)
        return session.scalars(statement).all()
    
    @classmethod
    def search(cls, name, brand):
        results = {}
        name_results_list = []
        brand_results_list = []
        if name:
            result = session.scalars(Select(cls).where(cls.deleted==False, cls.name.icontains(name))).all()
            if result not in name_results_list:
                name_results_list.append(result)
        if brand:
            result = session.scalars(Select(cls).where(cls.deleted==False, cls.brand.icontains(brand))).all()
            if result not in brand_results_list:
                brand_results_list.append(result)
        if name_results_list:
            results['Name'] = name_results_list
        if brand_results_list:
            results['Brand'] = brand_results_list
        return results


class Role(Base):
    __tablename__ = 'role'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False, unique=True)
    permission_id = relationship(
        'Permission', back_populates='role_id', secondary='roles_permissions', lazy='dynamic')
    user_id = relationship('User', back_populates='role_id',
                           secondary='users_roles', lazy='dynamic')
    
    @classmethod
    def from_name(cls, name):
        return session.scalar(Select(cls).where(cls.name == name))
    
    def role_got_permission(permission_required, email_of_user):
        permission_object = Permission.from_scope(permission_required)
        permission_id = permission_object.id
        users_all_role = User.get_all_role(email_of_user)
        for role in users_all_role:
            result = session.scalar(Select(RolePermission).where(
                RolePermission.role_id==role.id,
                RolePermission.permission_id == permission_id
                ))
            if result:
                return True
        return False


class Permission(Base):
    __tablename__ = 'permission'
    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(nullable=False, unique=True)
    role_id = relationship('Role', back_populates='permission_id',
                           secondary='roles_permissions', lazy='dynamic')

    @classmethod
    def from_scope(cls, scope):
        return session.scalar(Select(cls).where(cls.scope == scope))

class UserRole(Base):
    __tablename__ = 'users_roles'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id = mapped_column('user_id', Integer, ForeignKey('user.id'))
    role_id = mapped_column('role_id', Integer, ForeignKey('role.id'))


class RolePermission(Base):
    __tablename__ = 'roles_permissions'
    id: Mapped[int] = mapped_column(primary_key=True)
    permission_id = mapped_column(
        'permission_id', Integer, ForeignKey('permission.id'))
    role_id = mapped_column('role_id', Integer, ForeignKey('role.id'))
