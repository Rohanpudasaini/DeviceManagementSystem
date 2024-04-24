from fastapi import HTTPException
from sqlalchemy import DateTime, ForeignKey, Integer, ARRAY, String, Select, func
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from utils.helper_function import (
    check_for_null_or_deleted,
    generate_password,
    normal_response,
    error_response,
)
from utils.schema import Designation, DeviceStatus, DeviceType, Purpose, RoleType
import datetime
from database.database_connection import session, try_session_commit
from auth import auth
from utils import constant_messages
from utils.logger import logger


class Base(DeclarativeBase):
    pass


class MaintenanceHistory(Base):
    __tablename__ = "maintenance_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    description: Mapped[str]
    purpose: Mapped[Purpose]
    cost: Mapped[int] = mapped_column(nullable=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"))
    devices = relationship("Device", back_populates="maintenance_record")
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    reported_by = relationship(
        "User", foreign_keys=[user_id], backref="reported_device"
    )
    sent_for_repair = mapped_column(DateTime)
    returned_from_repair = mapped_column(DateTime)

    @classmethod
    def add(cls, mac_address, email, **kwargs):
        user_email = email
        device_to_repair_mac_address = mac_address
        logger.info(
            f"User with email {user_email} have requested to repair device with mac address {device_to_repair_mac_address}."
        )
        device_to_repair = Device.from_mac_address(device_to_repair_mac_address)
        user = User.from_email(user_email)
        if not user or not device_to_repair:
            # if not device_to_repair.status == DeviceStatus.ACTIVE:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found(
                        "device", "mac address, as it is flagged as not available"
                    ),
                ),
            )
        kwargs["devices"] = device_to_repair
        kwargs["reported_by"] = user

        object_to_add = cls(**kwargs)
        session.add(object_to_add)
        try_session_commit(session)
        device_to_repair.available = False
        device_to_repair.status = DeviceStatus.INACTIVE
        device_to_repair.user = None
        session.add(device_to_repair)
        try_session_commit(session)
        logger.info(
            f"Successfully given device with mac address {device_to_repair_mac_address} to repair"
        )
        return "Successfully Given For Repair"

    @classmethod
    def update(cls, mac_address, **kwargs):
        mac_address = mac_address
        returned_device = Device.from_mac_address(mac_address)
        if not returned_device:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("device", "mac_address"),
                ),
            )
        device_id = returned_device.id
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id, cls.returned_from_repair == None
            )
        )
        for key, values in kwargs.items():
            if values is not None:
                setattr(record_to_update, key, values)
        # returned_device = Device.from_id(device_id)
        user_object = User.from_id(record_to_update.user_id)
        returned_device.user = user_object
        returned_device.status = DeviceStatus.ACTIVE
        session.add(record_to_update)
        session.add(returned_device)
        try_session_commit(session)
        return f"The device with id {device_id} returned Successfully"
    
    @classmethod
    def device_maintenance_history(cls, device_id):
        return session.scalars(Select(cls).where(cls.device_id == device_id)).all()

class User(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False, deferred=True)
    temp_password: Mapped[str] = mapped_column(nullable=True, deferred=True)
    temp_password_created_at = mapped_column(DateTime, nullable=True, deferred=True)
    first_name: Mapped[str]
    last_name: Mapped[str]
    phone_no: Mapped[str]
    address: Mapped[str]
    city: Mapped[str]
    postal_code: Mapped[str]
    profile_pic_url: Mapped[str] = mapped_column(nullable=True)
    creation_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC)
    )
    allow_notification: Mapped[bool] = mapped_column(default=True)
    designation: Mapped[Designation] = mapped_column(nullable=True)
    deleted: Mapped[bool] = mapped_column(default=False, deferred=True)
    deleted_at = mapped_column(DateTime, nullable=True, deferred=True)
    role_id = relationship(
        "Role", back_populates="user_id", secondary="users_roles", lazy="dynamic"
    )
    default_password: Mapped[bool] = mapped_column(default=True, deferred=True)
    devices = relationship("Device", back_populates="user")

    @hybrid_property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @classmethod
    def add(cls, **kwargs):
        # username, email, password, message
        password = generate_password(12)
        kwargs["password"] = auth.hash_password(password)
        role_to_add = kwargs.get("role")
        kwargs.pop("role")
        user_to_add = cls(**kwargs)
        if role_to_add:
            role = Role.from_name(role_to_add)
            if role:
                user_to_add.role_id = [role]
            else:
                role = Role.from_name("viewer")
                user_to_add.role_id = [role]

        session.add(user_to_add)
        try_session_commit(session)
        logger.info(msg=f"User with username {user_to_add.full_name} Added Successfully")
        return (
            password,
            user_to_add.full_name,
            normal_response(
                message="User added successfully, Please find your temporary password in mail"
            ),
        )

    @classmethod
    def change_password(cls, email, **kwargs):
        user_to_update = cls.from_email(email)
        if user_to_update:
            if user_to_update.default_password:
                if kwargs["new_password"] == user_to_update.password:
                    logger.warning("Same password as old password")
                    raise HTTPException(
                        status_code=409,
                        detail=error_response(
                            message="Same Password",
                            error="New password same as old password",
                        ),
                    )
                if kwargs["old_password"] == user_to_update.password:
                    user_to_update.password = auth.hash_password(kwargs["new_password"])
                    user_to_update.default_password = False
                    session.add(user_to_update)
                    try_session_commit(session)
                    logger.info("Password Changed Successfully")
                    return "Password Changed Successfully, Enjoy your account"

                raise HTTPException(
                    status_code=401,
                    detail=error_response(
                        message=constant_messages.UNAUTHORIZED,
                        error=constant_messages.UNAUTHORIZED_MESSAGE,
                    ),
                )

            if auth.verify_password(kwargs["old_password"], user_to_update.password):
                if auth.verify_password(
                    kwargs["new_password"], user_to_update.password
                ):
                    logger.warning("Same password as old password")
                    raise HTTPException(
                        status_code=409,
                        detail=error_response(
                            message="Same Password",
                            error="New password same as old password",
                        ),
                    )
                user_to_update.password = auth.hash_password(kwargs["new_password"])
                user_to_update.default_password = False
                try_session_commit(session)
                logger.info("Password Changed Successfully")
                return "Password Changed Successfully, Enjoy your account"

            logger.warning("Password don't match")
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message=constant_messages.UNAUTHORIZED,
                    error=constant_messages.UNAUTHORIZED_MESSAGE,
                ),
            )

    @classmethod
    def reset_password(cls, email, new_password, confirm_password):
        if new_password != confirm_password:
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message="Different Password",
                    error="New password and confirm password must be same",
                ),
            )
        user_object = cls.from_email(email)
        check_for_null_or_deleted(user_object, "user", "email")
        password = auth.hash_password(new_password)
        user_object.password = password
        user_object.temp_password = None
        user_object.temp_password_created_at = None
        user_object.default_password = False
        session.add(user_object)
        try_session_commit(session)
        return normal_response(message="Password changed successfully!")

    @classmethod
    def update(cls, email, **kwargs):
        user_to_update = cls.from_email(email)
        role_to_add = kwargs["role"]
        if role_to_add:
            final_role = Role.from_name(role_to_add)
            if final_role:
                user_to_update.role_id = [final_role]
        for key, value in kwargs.items():
            if value is not None:
                # print(value)
                setattr(user_to_update, key, value)
        session.add(user_to_update)
        try_session_commit(session)
        logger.info(msg=f"{user_to_update.full_name} updated Successful")
        return "Update Successful"

    @classmethod
    def current_device(cls, token: dict):

        email = token["user_identifier"]
        if not email:
            # return normal_response(message ="Authentication failed .please check your token !")
            raise HTTPException(
                status_code=401,
                detail=error_response(
                    message=constant_messages.TOKEN_ERROR,
                    error=constant_messages.TOKEN_VERIFICATION_FAILED,
                ),
            )
        user = session.scalar(Select(cls).where(cls.email == email))

        if not user:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("user", "email"),
                ),
            )

        devices = user.devices
        if not devices:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=f"No device is associated with the {user.full_name}",
                ),
            )

        return devices

    @classmethod
    def current_devices_by_user_id(cls, user_id):
        user = session.scalar(Select(cls).filter(cls.id == user_id))
        if not user:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("user", "id"),
                ),
            )

        devices = user.devices
        if not devices:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message="This user haven't borrowed any devices.",
                    error=f"No device is associated with the {user.full_name}",
                ),
            )
        return devices

    @classmethod
    def delete(cls, **args):
        user_to_delete = cls.from_email(args["identifier"])
        if user_to_delete.devices:
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message="Conflict",
                    error="The user have some devices assigned to them, can't delete the user",
                ),
            )
        user_to_delete.deleted = True
        user_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(user_to_delete)
        try_session_commit(session)
        logger.info(msg=f"{user_to_delete.full_name} deleted Successfully")
        return "Deleted Successfully"

    # @classmethod
    # def get_all(cls, skip, limit):
    #     statement = Select(cls).where(cls.deleted == False).offset(skip).limit(limit)
    #     count = session.scalar(
    #         Select(func.count()).select_from(cls).where(cls.deleted == False)
    #     )
    #     return session.scalars(statement).all(), count
    
    @classmethod
    def get_all(cls, page_number, page_size):
        statement = (
            Select(cls)
            .where(cls.deleted == False)
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )
        count = session.scalar(
            Select(func.count()).select_from(cls).where(cls.deleted == False)
        )
        return session.scalars(statement).all(), count

    @classmethod
    def from_id(cls, id):
        return session.scalar(Select(cls).where(cls.id == id, cls.deleted == False))

    @classmethod
    def from_email(cls, email):
        return session.scalar(
            Select(cls).where(cls.email == email, cls.deleted == False)
        )

    @classmethod
    def login(cls, **kwargs):
        user_object = cls.from_email(kwargs["email"])
        check_for_null_or_deleted(user_object, "email", "User")
        is_valid = auth.verify_password(kwargs["password"], user_object.password)
        if is_valid:
            access_token, refresh_token = auth.generate_JWT(email=user_object.email)
            if not user_object.default_password:
                # print(user_object.role_id)
                role_id = session.scalars(
                    Select(UserRole.role_id).where(UserRole.user_id == user_object.id)
                ).first()
                role_name = Role.name_from_id(role_id)
                user_object.temp_password = None
                user_object.temp_password_created_at = None
                logger.info("Login Successful")
                return normal_response(
                    message="Login Successful",
                    data={
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "fullname": user_object.full_name,
                        "profile_pic_url": user_object.profile_pic_url,
                        "role": role_name,
                    },
                )
            logger.warning("Default password, redirection to change password")
            return normal_response(
                message="Default password used to login, please change password, use the below provided token to reset password at /reset_password",
                data={"token": auth.generate_otp_JWT(kwargs["email"])},
            )
        logger.error("Invalid Credentials, checking temp password")
        if user_object.temp_password:
            result = auth.verify_password(kwargs["password"], user_object.temp_password)
            if result:
                if (
                    user_object.temp_password_created_at + datetime.timedelta(days=5)
                ).date() > datetime.datetime.now().date():
                    access_token = auth.generate_otp_JWT(kwargs["email"])
                    return normal_response(
                        message="Temporary password is used, please use this access token to change password at /reset_password.",
                        data={"token": access_token},
                    )
        raise HTTPException(
            status_code=401,
            detail=error_response(
                message="Unauthorized", error="Invalid credentials !"
            ),
        )

    @classmethod
    def get_all_role(cls, email):
        user_object = cls.from_email(email)
        return user_object.role_id.all()


class DeviceRequestRecord(Base):
    __tablename__ = "device_request_records"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    borrowed_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC)
    )
    returned_date = mapped_column(DateTime, nullable=True, default=None)
    expected_return_date = mapped_column(DateTime)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"), nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    device = relationship("Device", backref="record", foreign_keys=[device_id])
    user = relationship("User", backref="record", foreign_keys=[user_id])

    @hybrid_property
    def is_returned(self):
        if self.returned_date:
            return True
        return False

    @classmethod
    def user_record(cls, id):
        return session.scalars(Select(cls).where(cls.user_id == id)).all()

    @classmethod
    def allot_to_user(cls, user_email, mac_address):
        device_to_allot = Device.from_mac_address(mac_address)
        if device_to_allot:
            device_id = device_to_allot.id
        else:
            return HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("device", "mac address"),
                ),
            )
        logger.info(
            f"Trying to allot a device with device id {device_id} to user \
            with email {user_email}"
        )
        # device_to_allot = Device.from_id(device_id)
        if not device_to_allot:
            logger.error(f"Can't find the device with device id {device_id}")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("device", "device id"),
                ),
            )
        requested_user = User.from_email(user_email)
        if not requested_user:
            logger.error(f"Can't find the user with email {user_email}")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("user", "user id"),
                ),
            )
        if not device_to_allot.deleted:
            if device_to_allot.available:
                if device_to_allot.status.value != "active":
                    logger.error("The device with device id {device_id} is not active")
                    raise HTTPException(
                        status_code=404,
                        detail=error_response(
                            message=constant_messages.REQUEST_NOT_FOUND,
                            error=constant_messages.request_not_found(
                                "device", "device id"
                            ),
                        ),
                    )
                device_to_allot.user = requested_user
                session.add(device_to_allot)
                try_session_commit(session)
                device_to_allot.available = False
                add_record = cls(
                    expected_return_date=datetime.datetime.now(tz=datetime.UTC)
                    + datetime.timedelta(days=30),
                    device=device_to_allot,
                    user=requested_user,
                )
                session.add(add_record)
                try_session_commit(session)
                logger.info(
                    f"Successfully allot device with id {device_id} to user with email {user_email}"
                )
                return "successfully alloted device"
            logger.error("The device is no longer available")
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message=constant_messages.INSUFFICIENT_RESOURCES,
                    error=constant_messages.insufficient_resources("device"),
                ),
            )
        logger.error(f"Device with device id {device_id} is already deleted")
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constant_messages.DELETED_ERROR,
                error=constant_messages.DELETED_ERROR_MESSAGE,
            ),
        )

    @classmethod
    def return_device(cls, user_email, mac_address):
        device_id = Device.from_mac_address(mac_address)
        if device_id:
            device_id = device_id.id
        else:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("device", "mac address"),
                ),
            )
        logger.info(
            f"Trying to return device with id {device_id} by user with id {user_email}"
        )
        device_to_return = Device.from_id(device_id)
        if not device_to_return:
            logger.error("Device not found")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("device", "device id"),
                ),
            )
        returned_user = User.from_email(user_email)
        if not returned_user:
            logger.error("User not found")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("user", "email"),
                ),
            )
        device_to_return.user = None
        device_to_return.available = True
        session.add(device_to_return)
        try_session_commit(session)
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id,
                cls.user_id == returned_user.id,
                cls.returned_date == None,
            )
        )
        if record_to_update:
            record_to_update.returned_date = datetime.datetime.now(tz=datetime.UTC)
            session.add(record_to_update)
            try_session_commit(session)
            logger.info(f"{user_email} returned device with id {device_id}")
            return "Device Returned Successfully"
        logger.error(
            f"The user {user_email} have already returned the device with id {device_id}"
        )
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constant_messages.REQUEST_NOT_FOUND,
                error=constant_messages.request_not_found(
                    "Request Record", "user id or device id or is already returned"
                ),
            ),
        )

    @classmethod
    def device_owner_history(cls, device_id):
        return session.scalars(Select(cls).where(cls.device_id == device_id)).all()

class Device(Base):
    __tablename__ = "device"
    id: Mapped[int] = mapped_column(primary_key=True)
    mac_address: Mapped[str] = mapped_column(nullable=False, unique=True)
    name: Mapped[str] = mapped_column(nullable=False)
    brand: Mapped[str] = mapped_column(nullable=False)
    price: Mapped[float] = mapped_column(nullable=False)
    description: Mapped[str]
    available: Mapped[bool] = mapped_column(default=True)
    status: Mapped[DeviceStatus] = mapped_column(default=DeviceStatus.ACTIVE)
    bill_image: Mapped[str]
    product_images = mapped_column(ARRAY(String))
    purchase_date = mapped_column(
        DateTime, default=datetime.datetime.now(tz=datetime.UTC)
    )
    type: Mapped[DeviceType]
    deleted: Mapped[bool] = mapped_column(default=False, deferred=True)
    deleted_at = mapped_column(DateTime, nullable=True, deferred=True)
    specification = mapped_column(ARRAY(String))
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    user = relationship("User", back_populates="devices")
    maintenance_record = relationship("MaintenanceHistory", back_populates="devices")
    # record = relationship('DeviceRequestRecord', back_populates='device')

    @classmethod
    def add(cls, **kwargs):
        device_to_add = cls(**kwargs)
        session.add(device_to_add)
        try_session_commit(session)
        logger.info({"success": "Device Added Successfully", "device_details": kwargs})
        return "Device Added Successfully"

    @classmethod
    def update(cls, mac_address, **kwargs):
        device_to_update = cls.from_mac_address(mac_address)
        if not device_to_update:
            logger.error(f"No device found with mac address {kwargs['mac_address']}")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constant_messages.REQUEST_NOT_FOUND,
                    error=constant_messages.request_not_found("Device", "mac address"),
                ),
            )
        for key, value in kwargs.items():
            if value:
                setattr(device_to_update, key, value)
        session.add(device_to_update)
        try_session_commit(session)
        logger.info(
            {"success": "Device Updated Successfully", "device_details": kwargs}
        )
        return "Update Successful"

    @classmethod
    def delete(cls, **kwargs):
        device_to_delete = cls.from_mac_address(kwargs["identifier"])
        if device_to_delete.user_id:
            logger.info("The device already assigned to some user, can't delete it")
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message="Conflict",
                    error="The device already assigned to some user, can't delete it",
                ),
            )
        if device_to_delete.status == DeviceStatus.INACTIVE:
            logger.info(
                "The device already might be in repair or not available, can't delete it"
            )
            raise HTTPException(
                status_code=409,
                detail=error_response(
                    message="Conflict",
                    error="The device already might be in repair or not available, can't delete it",
                ),
            )

        device_to_delete.available = False
        device_to_delete.deleted = True
        device_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(device_to_delete)
        try_session_commit(session)
        logger.info(
            {"success": "Device Deleted Successfully", "device_details": kwargs}
        )
        return "Deleted Successfully"

    @classmethod
    def from_id(cls, id):
        return session.scalar(Select(cls).where(cls.id == id, cls.deleted == False))

    @classmethod
    def from_category(cls,category_name):
        return session.scalars(Select(cls).where(cls.deleted == False, cls.type==category_name.upper())).all()


    @classmethod
    def from_mac_address(cls, mac_address):
        return session.scalar(
            Select(cls).where(cls.mac_address == mac_address, cls.deleted == False)
        )

    # # TODO:validation is required to do there ? if the concept is right then we will continue right yes !

    # @classmethod  # query means the device right ?
    # def get_all_devices(
    #     cls, name=None, brand=None, page_num: int = 1, page_size: int = 10
    # ):
    #     query = session.query(cls).filter(cls.deleted == False)

    #     if name:
    #         query = query.filter(cls.name.icontains(name))
    #     if brand:
    #         query = query.filter(cls.brand.icontains(brand))

    #     total_devices = query.count()
    #     devices = query.offset((page_num - 1) * page_size).limit(page_size).all()

    #     if not devices and (name or brand):
    #         raise HTTPException(
    #             status_code=404,
    #             detail="Device with the specified name and brand not found !",
    #         )

    #     response = {
    #         "pagination": {
    #             "total": total_devices,
    #             "count": len(devices),
    #         },
    #         "devices": devices,
    #     }

    #     if page_num > 1:

    #         response["pagination"][
    #             "previous"
    #         ] = f"/devices?page_num={page_num-1}&page_size={page_size}"
    #         devices
    #     else:
    #         response["pagination"]["previous"] = None

    #     if total_devices > page_num * page_size:
    #         response["pagination"][
    #             "next"
    #         ] = f"/devices?page_num={page_num+1}&page_size={page_size}"
    #     else:
    #         raise HTTPException(status_code=404, detail="No result found  !")

    @classmethod
    def get_all(cls, page_number, page_size):
        statement = (
            Select(cls)
            .where(cls.available == True, cls.deleted == False)
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )
        count = session.scalar(
            Select(func.count())
            .select_from(cls)
            .where(cls.available == True, cls.deleted == False)
        )
        result = session.scalars(statement).all()
        return result, count

    @classmethod
    def search_device(cls, name, brand):
        if name and brand:
            devices = session.scalars(
                Select(cls).filter(
                    cls.deleted == False,
                    cls.name.icontains(name),
                    cls.brand.icontains(brand),
                )
            ).all()
            if devices:
                return devices
            raise HTTPException(
                status_code=404, detail="Device with name and brand not found   !"
            )
        if name:
            devices = session.scalars(
                Select(cls).filter(cls.deleted == False, cls.name.icontains(name))
            ).all()
            if not devices:
                raise HTTPException(
                    status_code=404, detail=f"Device with the name is not found !"
                )
            return devices
        elif brand:
            devices = session.scalars(
                Select(cls).filter(cls.deleted == False, cls.brand.icontains(brand))
            ).all()
            if not devices:
                raise HTTPException(
                    status_code=404, detail="Device with the Brand not found   !"
                )
            return devices
        else:
            raise HTTPException(status_code=404, detail="No result found  !")


class Role(Base):
    __tablename__ = "role"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[RoleType] = mapped_column(nullable=False, unique=True)
    permission_id = relationship(
        "Permission",
        back_populates="role_id",
        secondary="roles_permissions",
        lazy="dynamic",
    )
    user_id = relationship(
        "User", back_populates="role_id", secondary="users_roles", lazy="dynamic"
    )

    @classmethod
    def from_name(cls, name):
        return session.scalar(Select(cls).where(cls.name == name))

    @classmethod
    def name_from_id(cls, id):
        return session.scalar(Select(cls.name).where(cls.id == id))

    def role_got_permission(permission_required, email_of_user):
        permission_object = Permission.from_scope(permission_required)
        permission_id = permission_object.id
        users_all_role = User.get_all_role(email_of_user)
        for role in users_all_role:
            result = session.scalar(
                Select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission_id,
                )
            )
            if result:
                return True
        return False


class Permission(Base):
    __tablename__ = "permission"
    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(nullable=False, unique=True)
    role_id = relationship(
        "Role",
        back_populates="permission_id",
        secondary="roles_permissions",
        lazy="dynamic",
    )

    @classmethod
    def from_scope(cls, scope):
        return session.scalar(Select(cls).where(cls.scope == scope))


class UserRole(Base):
    __tablename__ = "users_roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id = mapped_column("user_id", Integer, ForeignKey("user.id"))
    role_id = mapped_column("role_id", Integer, ForeignKey("role.id"))


class RolePermission(Base):
    __tablename__ = "roles_permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    permission_id = mapped_column("permission_id", Integer, ForeignKey("permission.id"))
    role_id = mapped_column("role_id", Integer, ForeignKey("role.id"))
