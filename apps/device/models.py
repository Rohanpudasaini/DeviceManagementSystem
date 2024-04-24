from fastapi import HTTPException
from sqlalchemy import DateTime, ForeignKey, ARRAY, String, Select, func
from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from core.utils import (
    error_response
)
from apps.device.schemas import DeviceStatus, DeviceType, Purpose
import datetime
from core.db import session, handle_db_transaction
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found(
                        "device", "mac address, as it is flagged as not available"
                    ),
                ),
            )
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
    def update(cls, mac_address, **kwargs):
        mac_address = mac_address
        returned_device = Device.from_mac_address(mac_address)
        if not returned_device:
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "mac_address"),
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
        handle_db_transaction(session)
        return f"The device with id {device_id} returned Successfully"
    
    @classmethod
    def device_maintenance_history(cls, device_id):
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "mac address"),
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "device id"),
                ),
            )
        requested_user = User.from_email(user_email)
        if not requested_user:
            logger.error(f"Can't find the user with email {user_email}")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("user", "user id"),
                ),
            )
        if not device_to_allot.deleted:
            if device_to_allot.available:
                if device_to_allot.status.value != "active":
                    logger.error("The device with device id {device_id} is not active")
                    raise HTTPException(
                        status_code=404,
                        detail=error_response(
                            message=constants.REQUEST_NOT_FOUND,
                            error=constants.request_not_found(
                                "device", "device id"
                            ),
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
                detail=error_response(
                    message=constants.INSUFFICIENT_RESOURCES,
                    error=constants.insufficient_resources("device"),
                ),
            )
        logger.error(f"Device with device id {device_id} is already deleted")
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constants.DELETED_ERROR,
                error=constants.DELETED_ERROR_MESSAGE,
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "mac address"),
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("device", "device id"),
                ),
            )
        returned_user = User.from_email(user_email)
        if not returned_user:
            logger.error("User not found")
            raise HTTPException(
                status_code=404,
                detail=error_response(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("user", "email"),
                ),
            )
        device_to_return.user = None
        device_to_return.available = True
        session.add(device_to_return)
        handle_db_transaction(session)
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
            handle_db_transaction(session)
            logger.info(f"{user_email} returned device with id {device_id}")
            return "Device Returned Successfully"
        logger.error(
            f"The user {user_email} have already returned the device with id {device_id}"
        )
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constants.REQUEST_NOT_FOUND,
                error=constants.request_not_found(
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
        handle_db_transaction(session)
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
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("Device", "mac address"),
                ),
            )
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
        handle_db_transaction(session)
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
                    status_code=404, detail="Device with the name is not found !"
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



