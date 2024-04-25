from fastapi import HTTPException
from sqlalchemy import DateTime, ForeignKey, ARRAY, String, Select, func
from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from apps.user.models import User
from core.utils import response_model
from apps.device.schemas import DeviceStatus, DeviceType, Purpose
import datetime
from core.db import handle_db_transaction, get_session
from core import constants
from core.logger import logger
from core.db import Base


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
    def add(cls, session, mac_address, email, **kwargs):
        user_email = email
        device_to_repair_mac_address = mac_address
        logger.info(
            f"User with email {user_email} have requested to repair device with mac address {device_to_repair_mac_address}."
        )
        device_to_repair = Device.from_mac_address(
            session, device_to_repair_mac_address
        )
        if (
            not device_to_repair.available
            or device_to_repair.status == DeviceStatus.INACTIVE
        ):
            raise HTTPException(
                status_code=409,
                detail=response_model(
                    message="Device In Maintenance",
                    error="The device you have request for is in maintenance",
                ),
            )
        user = User.from_email(user_email)
        kwargs["devices"] = device_to_repair
        kwargs["reported_by"] = user

        object_to_add = cls(**kwargs)
        session.add(object_to_add)
        handle_db_transaction(session)
        device_to_repair.available = False
        device_to_repair.status = DeviceStatus.INACTIVE
        device_to_repair.user = None
        session.add(device_to_repair)
        handle_db_transaction(session)
        logger.info(
            f"Successfully given device with mac address {device_to_repair_mac_address} to repair"
        )
        return "Successfully Given For Repair"

    @classmethod
    def update(cls, session, mac_address, **kwargs):
        mac_address = mac_address
        returned_device = Device.from_mac_address(session, mac_address)
        device_id = returned_device.id
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id,
                cls.returned_from_repair == None,  # noqa: E711
            )
        )
        if record_to_update:
            for key, values in kwargs.items():
                if values is not None:
                    setattr(record_to_update, key, values)
            # returned_device = Device.from_id(device_id)
            user_object = User.from_id(session, record_to_update.user_id)
            returned_device.user = user_object
            returned_device.status = DeviceStatus.ACTIVE
            session.add(record_to_update)
            session.add(returned_device)
            handle_db_transaction(session)
            return f"The device with id {device_id} returned Successfully"
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found("record", "for that device"),
            ),
        )

    @classmethod
    def device_maintenance_history(cls, session, device_id):
        return session.scalars(Select(cls).where(cls.device_id == device_id)).all()


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
    def allot_to_user(cls, session, user_email, mac_address):
        device_to_allot = Device.from_mac_address(session, mac_address)
        device_id = device_to_allot.id
        logger.info(
            f"Trying to allot a device with device id {device_id} to user \
            with email {user_email}"
        )
        requested_user = User.from_email(session, user_email)
        if not device_to_allot.deleted:
            if device_to_allot.available:
                if device_to_allot.status.value != "active":
                    logger.error("The device with device id {device_id} is not active")
                    raise HTTPException(
                        status_code=404,
                        detail=response_model(
                            message=constants.REQUEST_NOT_FOUND,
                            error=constants.request_not_found("device", "device id"),
                        ),
                    )
                device_to_allot.user = requested_user
                session.add(device_to_allot)
                handle_db_transaction(session)
                device_to_allot.available = False
                add_record = cls(
                    expected_return_date=datetime.datetime.now(tz=datetime.UTC)
                    + datetime.timedelta(days=30),
                    device=device_to_allot,
                    user=requested_user,
                )
                session.add(add_record)
                handle_db_transaction(session)
                logger.info(
                    f"Successfully allot device with id {device_id} to user with email {user_email}"
                )
                return "successfully alloted device"
            logger.error("The device is no longer available")
            raise HTTPException(
                status_code=409,
                detail=response_model(
                    message=constants.INSUFFICIENT_RESOURCES,
                    error=constants.insufficient_resources("device"),
                ),
            )
        logger.error(f"Device with device id {device_id} is already deleted")
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.DELETED_ERROR,
                error=constants.DELETED_ERROR_MESSAGE,
            ),
        )

    @classmethod
    def return_device(cls, session, user_email, mac_address):
        device_to_return = Device.from_mac_address(session, mac_address)
        device_id = device_to_return.id
        logger.info(
            f"Trying to return device with id {device_id} by user with id {user_email}"
        )
        returned_user = User.from_email(session, user_email)
        device_to_return.user = None
        device_to_return.available = True
        session.add(device_to_return)
        handle_db_transaction(session)
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id,
                cls.user_id == returned_user.id,
                cls.returned_date == None,  # noqa: E711
            )
        )
        if record_to_update:
            record_to_update.returned_date = datetime.datetime.now(tz=datetime.UTC)
            session.add(record_to_update)
            handle_db_transaction(session)
            logger.info(f"{user_email} returned device with id {device_id}")
            return "Device Returned Successfully"
        logger.error(
            f"The user {user_email} have already returned the device with id {device_id}"
        )
        raise HTTPException(
            status_code=404,
            detail=response_model(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found(
                    "Request Record", "the given info or the device is already returned"
                ),
            ),
        )

    @classmethod
    def device_owner_history(cls, session, device_id):
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
    def add(cls, session, **kwargs):
        device_to_add = cls(**kwargs)
        device_exists = session.scalar(
            Select(cls).where(cls.mac_address == kwargs["mac_address"])
        )
        if not device_exists:
            session.add(device_to_add)
            handle_db_transaction(session)
            logger.info(
                {"success": "Device Added Successfully", "device_details": kwargs}
            )
            return "Device Added Successfully"
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.INTEGRITY_ERROR,
                error=constants.INTEGRITY_ERROR_MESSAGE,
            ),
        )

    @classmethod
    def update(cls, session, mac_address, **kwargs):
        device_to_update = cls.from_mac_address(session, mac_address)
        for key, value in kwargs.items():
            if value:
                setattr(device_to_update, key, value)
        session.add(device_to_update)
        handle_db_transaction(session)
        logger.info(
            {"success": "Device Updated Successfully", "device_details": kwargs}
        )
        return "Update Successful"

    @classmethod
    def delete(cls, session, mac_address):
        device_to_delete = cls.from_mac_address(session, mac_address)
        device_to_delete.available = False
        device_to_delete.deleted = True
        device_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(device_to_delete)
        handle_db_transaction(session)
        logger.info(
            {"success": f"Device with id {device_to_delete.id} is deleted Successfully"}
        )
        return "Deleted Successfully"

    @classmethod
    def from_id(cls, session, id):
        result = session.scalar(Select(cls).where(cls.id == id, cls.deleted == False))  # noqa: E712
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "id"),
                ),
            )
        return result

    @classmethod
    def from_category(cls, session, category_name):
        result = session.scalars(
            Select(cls).where(cls.deleted == False, cls.type == category_name.upper()) # noqa: E712
        ).all()  
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "category"),
                ),
            )
        return result

    @classmethod
    def from_mac_address(cls, session, mac_address):
        result = session.scalar(
            Select(cls).where(cls.mac_address == mac_address, cls.deleted == False)  # noqa: E712
        )
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "mac address"),
                ),
            )
        return result

    @classmethod
    def get_all(cls, session, page_number, page_size):
        session = get_session()
        statement = (
            Select(cls)
            .where(cls.available == True, cls.deleted == False)  # noqa: E712
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )
        count = session.scalar(
            Select(func.count())
            .select_from(cls)
            .where(cls.available == True, cls.deleted == False)  # noqa: E712
        )
        result = session.scalars(statement).all()
        return result, count

    @classmethod
    def search_device(cls, session, name, brand):
        session = get_session()
        if name and brand:
            devices = session.scalars(
                Select(cls).filter(
                    cls.deleted == False,  # noqa: E712
                    cls.name.icontains(name),
                    cls.brand.icontains(brand),
                )
            ).all()
            return devices
        if name:
            devices = session.scalars(
                Select(cls).filter(cls.deleted == False, cls.name.icontains(name))  # noqa: E712
            ).all()
            return devices
        elif brand:
            devices = session.scalars(
                Select(cls).filter(cls.deleted == False, cls.brand.icontains(brand))  # noqa: E712
            ).all()
            return devices
