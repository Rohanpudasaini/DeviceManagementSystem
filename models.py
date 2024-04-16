from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import DateTime, ForeignKey, Integer, ARRAY, String, Select, func
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
    repair_requested = relationship(
        'User',
        foreign_keys=[maintainance_requested_user_id],
        backref='sent_for_repair'
        )
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
        logger.info(f"User with id {current_user_id} have requested to \
        maintain device with id {device_to_repair_id}.\
        The admin with id {requested_by_user_id} have accepted the request")
        device_to_repair = Device.from_id(device_to_repair_id)
        requested_by = User.from_id(requested_by_user_id)
        current_owner = User.from_id(current_user_id)
        if not requested_by and current_owner and device_to_repair:
            logger.error(
                f'Can\'t find user with id {requested_by_user_id} \
                or {current_user_id} \
                or the device with id {device_to_repair_id} found')
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found(
                            'users and device',
                            'user id and device id'
                        )
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
        device_to_repair.user = None
        session.add(device_to_repair)
        try_session_commit(session)
        logger.info(
            "Sucessfully given device with id {device_to_repair_id} to repair")
        return 'Sucessfully Given For Repair'
    
    @classmethod
    def update(cls, **kwargs):
        device_id = kwargs['device_id']
        kwargs.pop('device_id')
        record_to_update = session.scalar(Select(cls). where(
            cls.device_id== device_id,
            cls.returned_from_repair == None))
        for key, values in kwargs.items():
            if values is not None:
                setattr(record_to_update,key,values)
        returned_device = Device.from_id(device_id)
        user_object = User.from_id(record_to_update.current_device_owner_id)
        returned_device.user = user_object
        session.add(record_to_update)
        session.add(returned_device)
        try_session_commit(session)
        return f"The device with id {device_id} returned sucesfully"


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
    profile_pic_url: Mapped[str] = mapped_column(nullable=True)
    creation_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC))
    allow_notification: Mapped[bool] = mapped_column(default=True)
    designation: Mapped[Designation] = mapped_column(default=Designation.USER)
    deleted: Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime, nullable=True)
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
        role_to_add = kwargs.get('role')
        kwargs.pop('role')
        user_to_add = cls(**kwargs)
        if role_to_add:
            for role_given in role_to_add:
                role = Role.from_name(role_given)
                if role:
                    user_to_add.role_id.append(role)
                
        
        role = Role.from_name('Viewer')
        user_to_add.role_id.append(role)
        session.add(user_to_add)
        try_session_commit(session)
        logger.info(
            msg=f'User with username {user_to_add.full_name} Added Sucesully')
        return (user_to_add.full_name,
                user_to_add.email,
                password,
                'User Added Sucesully, please login using the password provided in your mail'
                )

    @classmethod
    def change_password(cls, email, **kwargs):
        user_to_update = cls.from_email(email)
        if auth.verify_password(
            kwargs['new_password'],
            user_to_update.password
        ):
            logger.warning("Same password as old password")
            raise HTTPException(
                status_code=409,
                detail={
                    'error_type': 'Same Password',
                    'error_message': "New password same as old password"
                }
            )
        if auth.verify_password(
            kwargs['old_password'],
            user_to_update.password
        ):
            user_to_update.password = auth.hash_password(
                kwargs['new_password'])
            user_to_update.default_password = False
            session.add(user_to_update)
            try_session_commit(session)
            logger.info('Password Changed Sucesfully')
            return "Password Changed Sucesfully, Enjoy your account"

    @classmethod
    def update(cls, **kwargs):
        user_to_update = cls.from_id(kwargs['id'])
        kwargs.pop('id')
        role_to_add = kwargs['role']
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
        if role_to_add:
            final_roles = [Role.from_name(role) for role in role_to_add]
            for final_role in final_roles:
                if final_role:
                    user_to_update.role_id.append(final_role)
        for key, value in kwargs.items():
            if value is not None:
                # print(value)
                setattr(user_to_update, key, value)
        session.add(user_to_update)
        try_session_commit(session)
        logger.info(msg=f'{user_to_update.full_name} updated Sucessful')
        return 'Update Sucessful'

    @classmethod
    def delete(cls, **args):
        user_to_delete = cls.from_id(args['id_to_delete'])
        user_to_delete.deleted = True
        user_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(user_to_delete)
        try_session_commit(session)
        logger.info(msg=f'{user_to_delete.full_name} deleted Sucessfully')
        return "Deleted Sucessfully"

    @classmethod
    def get_all(cls, skip, limit):
        statement = Select(cls).where(
            cls.deleted == False).offset(skip).limit(limit)
        count = session.scalar(Select(func.count()).select_from(cls).where(cls.deleted == False))
        return session.scalars(statement).all(), count

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
            access_token, refresh_token = auth.generate_JWT(
                email=user_object.email)
            if not user_object.default_password:
                logger.info("Login Sucessfull")
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'fullname': user_object.full_name,
                    'profile_pic_url': user_object.profile_pic_url,
                    'role': user_object.role_id.all()
                }
            logger.warning("Default password, redirection to change password")
            return RedirectResponse('/change_password')
        logger.error("Invalid Credentials")
        raise HTTPException(
            status_code=401,
            detail='Invalid Credentials'
        )

    @classmethod
    def verify_credential(cls, **kwargs):
        user_object = cls.from_email(kwargs['email'])
        check_for_null_or_deleted(user_object, 'email', 'User')
        is_valid = auth.verify_password(
            kwargs['password'], user_object.password)
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
    device_id: Mapped[int] = mapped_column(
        ForeignKey('device.id'), nullable=True)
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
        logger.info(
            f"Trying to allot a device with device id {device_id} to user \
            with userid {user_email}")
        device_to_allot = Device.from_id(device_id)
        if not device_to_allot:
            logger.error(f"Can't find the device with deviceid {device_id}")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found(
                            'device',
                            'device id')
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
                        'error_message': constant_messages.request_not_found(
                            'user',
                            'user id')
                    }
                }
            )
        if not device_to_allot.deleted:
            if device_to_allot.available:
                if device_to_allot.status.value != 'added':
                    logger.error(
                        "The device with device id {device_id} is not published")
                    raise HTTPException(
                        status_code=404,
                        detail={
                            'error': {
                                'error_type': constant_messages.REQUEST_NOT_FOUND,
                                'error_message': constant_messages.request_not_found(
                                    'device',
                                    'device id')
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
                logger.info(
                    f"Sucessfully allot device with id {device_id} to user with email {user_email}")
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
        logger.error(f"Device with device id {device_id} is already deleted")
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
    def return_device(cls, user_email, device_id):
        logger.info(
            f"Trying to return device with id {device_id} by user with id {user_email}")
        device_to_return = Device.from_id(device_id)
        if not device_to_return:
            logger.error("Device not found")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found(
                            'device',
                            'device id'
                        )
                    }
                }
            )
        returned_user = User.from_email(user_email)
        if not returned_user:
            logger.error("User not found")
            raise HTTPException(
                status_code=404,
                detail={
                    'error': {
                        'error_type': constant_messages.REQUEST_NOT_FOUND,
                        'error_message': constant_messages.request_not_found(
                            'user',
                            'email')
                    }
                }
            )
        device_to_return.user = None
        device_to_return.available = True
        session.add(device_to_return)
        try_session_commit(session)
        record_to_update = session.scalar(Select(cls).where(
            cls.device_id == device_id,
            cls.user_id == returned_user.id,
            cls.returned_date == None
            ))
        if record_to_update:
            record_to_update.returned_date = datetime.datetime.now(
                tz=datetime.UTC)
            session.add(record_to_update)
            try_session_commit(session)
            logger.info(f"{user_email} returned device with id {device_id}")
            return 'Device Returned Sucessfully'
        logger.error(
            f"The user {user_email} have already returned the device with id {device_id}")
        raise HTTPException(
            status_code=404,
            detail={
                'error': {
                    'error_type': constant_messages.REQUEST_NOT_FOUND,
                    'error_message': constant_messages.request_not_found(
                        'Request Record',
                        'user id or device id or is already returned')
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
    deleted: Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime, nullable=True)
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
        logger.info({"sucess": "Device Added Sucesfully",
                    "device_details": kwargs})
        return "Device Added Sucesfully"

    @classmethod
    def update(cls, **kwargs):
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
                setattr(device_to_update, key, value)
        session.add(device_to_update)
        try_session_commit(session)
        logger.info({"sucess": "Device Updated Sucesfully",
                    "device_details": kwargs})
        return 'Update Sucessful'

    @classmethod
    def delete(cls, **kwargs):
        device_to_delete = cls.from_id(kwargs['id_to_delete'])
        device_to_delete.deleted = True
        device_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(device_to_delete)
        try_session_commit(session)
        logger.info({"sucess": "Device Deleted Sucesfully",
                    "device_details": kwargs})
        return "Deleted Sucessfully"

    @classmethod
    def from_id(cls, id):
        return session.scalar(Select(cls).where(cls.id == id))

    @classmethod
    def get_all(cls, skip, limit):
        statement = Select(cls).where(
            cls.available == True,
            cls.deleted == False).offset(skip).limit(limit)
        count = session.scalar(Select(func.count()).select_from(cls).where(
            cls.available == True,
            cls.deleted == False
        ))
        result =  session.scalars(statement).all()
        return result, count

    @classmethod
    def search(cls, name, brand):
        results = {}
        name_results_list = []
        brand_results_list = []
        if name:
            result = session.scalars(Select(cls).where(
                cls.deleted == False, cls.name.icontains(name))).all()
            if result not in name_results_list:
                name_results_list.append(result)
        if brand:
            result = session.scalars(Select(cls).where(
                cls.deleted == False, cls.brand.icontains(brand))).all()
            if result not in brand_results_list:
                brand_results_list.append(result)
        if name_results_list:
            results['Name'] = name_results_list
        if brand_results_list:
            results['Brand'] = brand_results_list
        logger.info({"sucess": f"Search of name {name} and brand {brand} give following result",
                    "details": {
                        'name': [name.__dict__ for name in name_results_list],
                        'brand': [brand.__dict__ for brand in brand_results_list]
                    }})
        return results


class Role(Base):
    __tablename__ = 'role'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False, unique=True)
    permission_id = relationship(
        'Permission',
        back_populates='role_id',
        secondary='roles_permissions',
        lazy='dynamic')
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
                RolePermission.role_id == role.id,
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
