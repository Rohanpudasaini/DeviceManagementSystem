from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import DateTime, ForeignKey, ARRAY, String, Select, func
from sqlalchemy.orm import mapped_column, Mapped, relationship, defer
from sqlalchemy.ext.hybrid import hybrid_property
from apps.device.enum import RequestStatus
from apps.user.models import User
from core.utils import response_model
from apps.device.schemas import DeviceStatus, DeviceType, Purpose
import datetime
from core.db import handle_db_transaction
from core import constants
from core.logger import logger
from core.db import Base
from core.email import send_mail


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
    def add(cls, session, device_to_repair, user, **kwargs):
        logger.info(
            f"User with email {user.email} have requested to repair device with mac address {device_to_repair.mac_address}."
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
            f"Successfully given device with mac address {device_to_repair.mac_address} to repair"
        )
        return "Successfully Given For Repair"

    @classmethod
    def update(cls, session, returned_device, **kwargs):
        device_id = returned_device.id
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id,
                cls.returned_from_repair == None,  # noqa: E711
            )
        )
        if record_to_update:
            for key, values in kwargs.items():
                setattr(record_to_update, key, values)
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
        return session.scalars(
            Select(cls).where(cls.device_id == device_id).order_by(cls.id.desc())
        ).all()


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
    request_status: Mapped[RequestStatus] = mapped_column(server_default="pending")
    device = relationship("Device", backref="record", foreign_keys=[device_id])
    user = relationship("User", backref="record", foreign_keys=[user_id])

    @hybrid_property
    def is_returned(self):
        if self.returned_date:
            return True
        return False

    @classmethod
    def from_id(cls, session, id):
        return session.scalar(Select(cls).where(cls.id == id))

    @classmethod
    def allot_to_user(
        cls, session, requested_user, device_to_allot, expected_return_date
    ):
        device_id = device_to_allot.id
        logger.info(
            f"{requested_user.full_name} is requesting a device with id {device_id}"
        )
        add_record = cls(
            expected_return_date=expected_return_date,
            device=device_to_allot,
            user=requested_user,
        )
        session.add(add_record)
        handle_db_transaction(session)
        logger.info(
            f"Successfully requested device with id {device_id} to user with email {requested_user.email}"
        )
        return (
            "successfully requested device, please wait while admin check your request. \
You will be informed through mail about the result."
        )

    @classmethod
    def return_device(cls, session, returned_user, device_to_return):
        device_id = device_to_return.id
        logger.info(
            f"Trying to return device with id {device_id} by user with id {returned_user.email}"
        )
        device_to_return.user = None
        device_to_return.available = True
        record_to_update = session.scalar(
            Select(cls).where(
                cls.device_id == device_id,
                cls.user_id == returned_user.id,
                cls.request_status == RequestStatus.accepted,
                cls.returned_date == None,  # noqa: E711
            )
        )
        if record_to_update:
            record_to_update.returned_date = datetime.datetime.now(tz=datetime.UTC)
            session.add(record_to_update)
            session.add(device_to_return)
            handle_db_transaction(session)
            logger.info(f"{returned_user.email} returned device with id {device_id}")
            return "Device Returned Successfully"
        logger.error(
            f"The user {returned_user.email} have already returned the device with id {device_id}"
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
        return session.scalars(
            Select(cls).where(cls.device_id == device_id).order_by(cls.id.desc())
        ).all()

    @classmethod
    def pending_requests(cls, session, page_number, page_size):
        basic_data = session.scalars(
            Select(cls)
            .where(cls.request_status == RequestStatus.pending)
            .order_by(cls.id.asc())
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )
        count = session.scalar(
            Select(func.count())
            .select_from(cls)
            .where(cls.request_status == RequestStatus.pending)
        )
        results = []
        for data in basic_data:
            result = {
                "id": data.id,
                "borrowed_date": data.borrowed_date,
                "expected_return_date": data.expected_return_date,
                "full_name": data.user.full_name,
                "designation": data.user.designation,
                "device_name": data.device.name,
                "category": data.device.type,
            }
            results.append(result)
        return results, count

    @classmethod
    def accept_request(
        cls, session, request_to_update, backgroundtasks: BackgroundTasks
    ):
        device_requested = request_to_update.device
        alloted_to = request_to_update.user
        device_requested.user = alloted_to
        device_requested.available = False
        request_to_update.request_status = RequestStatus.accepted
        session.add_all([device_requested, alloted_to, request_to_update])
        handle_db_transaction(session=session)

        same_devices_requested = session.scalars(
            Select(cls).where(
                cls.device == device_requested,
                cls.request_status == RequestStatus.pending,
            )
        ).all()
        if same_devices_requested:
            for remaining_request in same_devices_requested:
                cls.reject_request(session, remaining_request, backgroundtasks)
        backgroundtasks.add_task(
            send_mail.confirmation_mail,
            email_to_send_to=request_to_update.user.email,
            username=request_to_update.user.full_name,
            device_name=request_to_update.device.name,
            device_model=request_to_update.device.mac_address,
            end_date=request_to_update.borrowed_date,
        )
        return "Device Alloted Successfully"

    @classmethod
    def reject_request(
        cls, session, request_to_update, backgroundtasks: BackgroundTasks
    ):
        request_to_update.request_status = RequestStatus.rejected
        session.add(request_to_update)
        handle_db_transaction(session=session)
        backgroundtasks.add_task(
            send_mail.rejection_mail,
            email_to_send_to=request_to_update.user.email,
            username=request_to_update.user.full_name,
            device_name=request_to_update.device.name,
            device_model=request_to_update.device.mac_address,
            requested_date=request_to_update.expected_return_date,
        )
        return "The device was not alloted"


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
    deleted: Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime, nullable=True)
    specification = mapped_column(ARRAY(String))
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    user = relationship("User", back_populates="devices")
    maintenance_record = relationship("MaintenanceHistory", back_populates="devices")

    @classmethod
    def add(cls, session, **kwargs):
        device_to_add = cls(**kwargs)
        session.add(device_to_add)
        handle_db_transaction(session)
        logger.info({"success": "Device Added Successfully", "device_details": kwargs})
        return "Device Added Successfully"

    @classmethod
    def assigned_device(cls, session, page_number, page_size):
        result = session.scalars(
            Select(cls)
            .where(cls.user_id != None)  # noqa: E712
            .order_by(cls.id.asc())
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )

        count = session.scalar(
            Select(func.count()).select_from(cls).where(cls.user_id != None)  # noqa: E712
        )
        return result, count

    @classmethod
    def update(cls, session, device_to_update, **kwargs):
        for key, value in kwargs.items():
            setattr(device_to_update, key, value)
        session.add(device_to_update)
        handle_db_transaction(session)
        logger.info(
            {"success": "Device Updated Successfully", "device_details": kwargs}
        )
        return "Update Successful"

    @classmethod
    def delete(cls, session, device_to_delete):
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
        result = session.scalar(
            Select(cls)
            .where(cls.id == id, cls.deleted == False)  # noqa: E712
            .options(
                defer(cls.deleted),
                defer(cls.deleted_at),
            )
        )
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
            Select(cls)
            .where(cls.deleted == False, cls.type == category_name.upper())  # noqa: E712
            .options(
                defer(cls.deleted),
                defer(cls.deleted_at),
            )
            .order_by(cls.id.asc())
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
    def from_mac_address(cls, session, mac_address, check=False):
        result = session.scalar(
            Select(cls)
            .where(cls.mac_address == mac_address, cls.deleted == False)  # noqa: E712
            .options(
                defer(cls.deleted),
                defer(cls.deleted_at),
            )
        )
        if not result:
            if check:
                return False
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
        statement = (
            Select(cls)
            .where(cls.available == True, cls.deleted == False)  # noqa: E712
            .options(
                defer(cls.deleted),
                defer(cls.deleted_at),
            )
            .order_by(cls.id.asc())
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
        if name and brand:
            devices = session.scalars(
                Select(cls)
                .filter(
                    cls.deleted == False,  # noqa: E712
                    cls.name.icontains(name),
                    cls.brand.icontains(brand),
                )
                .options(
                    defer(cls.deleted),
                    defer(cls.deleted_at),
                )
            ).all()
            return devices
        if name:
            devices = session.scalars(
                Select(cls)
                .filter(
                    cls.deleted == False,  # noqa: E712
                    cls.name.icontains(name),
                )
                .options(
                    defer(cls.deleted),
                    defer(cls.deleted_at),
                ),
            ).all()
            return devices
        elif brand:
            devices = session.scalars(
                Select(cls).filter(
                    cls.deleted == False,  # noqa: E712
                    cls.brand.icontains(brand).options(
                        defer(cls.deleted),
                        defer(cls.deleted_at),
                    ),
                )
            ).all()
            return devices
