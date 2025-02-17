from fastapi import HTTPException
from sqlalchemy import DateTime, ForeignKey, Integer, Select, func
from sqlalchemy.orm import mapped_column, Mapped, relationship, defer
from sqlalchemy.ext.hybrid import hybrid_property
from core.utils import (
    generate_password,
    response_model,
)
from apps.user.schemas import Designation, RoleType
import datetime
from core.db import handle_db_transaction
from apps.authentication import auth
from core import constants
from core.logger import logger
from core.db import Base


class User(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    temp_password: Mapped[str] = mapped_column(nullable=True)
    temp_password_created_at = mapped_column(DateTime, nullable=True)
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
    deleted: Mapped[bool] = mapped_column(default=False)
    deleted_at = mapped_column(DateTime, nullable=True)
    role_id = relationship(
        "Role", back_populates="user_id", secondary="users_roles", lazy="dynamic"
    )
    default_password: Mapped[bool] = mapped_column(default=True)
    devices = relationship("Device", back_populates="user")

    @hybrid_property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @classmethod
    def add(cls, session, **kwargs):
        password = generate_password(12)
        kwargs["password"] = auth.hash_password(password)
        role_to_add = kwargs.get("role")
        kwargs.pop("role")
        user_to_add = cls(**kwargs)
        if role_to_add:
            role = Role.from_name(session, role_to_add)
            if role:
                user_to_add.role_id = [role]
            else:
                role = Role.from_name(session, "viewer")
                user_to_add.role_id = [role]
        session.add(user_to_add)
        handle_db_transaction(session)
        logger.info(
            msg=f"User with username {user_to_add.full_name} Added Successfully"
        )
        return (
            password,
            user_to_add.full_name,
            response_model(
                message="User added successfully, Please find your temporary password in mail"
            ),
        )

    @classmethod
    def change_password(cls, session, user_to_update, new_password):
        user_to_update.password = auth.hash_password(new_password)
        user_to_update.default_password = False
        session.add(user_to_update)
        handle_db_transaction(session)
        logger.info("Password Changed Successfully")
        return "Password Changed Successfully, Enjoy your account"

    @classmethod
    def reset_password(cls, session, user_object, new_password):
        password = auth.hash_password(new_password)
        user_object.password = password
        user_object.temp_password = None
        user_object.temp_password_created_at = None
        user_object.default_password = False
        session.add(user_object)
        handle_db_transaction(session)
        return response_model(message="Password changed successfully!")

    @classmethod
    def update(cls, user_to_update, session, **kwargs):
        role_to_add = kwargs["role"]
        if role_to_add:
            final_role = Role.from_name(session, role_to_add)
            if final_role:
                user_to_update.role_id = [final_role]
        for key, value in kwargs.items():
            setattr(user_to_update, key, value)
        session.add(user_to_update)
        handle_db_transaction(session)
        logger.info(msg=f"{user_to_update.full_name} updated Successful")
        return "Update Successful"

    @classmethod
    def delete(cls, session, user_to_delete):
        user_to_delete.deleted = True
        user_to_delete.deleted_at = datetime.datetime.now(tz=datetime.UTC)
        session.add(user_to_delete)
        handle_db_transaction(session)
        logger.info(msg=f"{user_to_delete.full_name} deleted Successfully")
        return "Deleted Successfully"

    @classmethod
    def get_all(cls, session, page_number, page_size):
        statement = (
            Select(cls)
            .where(cls.deleted == False)  # noqa: E712
            .options(
                defer(cls.password),
                defer(cls.temp_password),
                defer(cls.temp_password_created_at),
                defer(cls.default_password),
                defer(cls.deleted),
                defer(cls.deleted_at),
                defer(cls.default_password),
            )
            .order_by(cls.id.asc())
            .offset(((page_number - 1) * page_size))
            .limit(page_size)
        )
        count = session.scalar(
            Select(func.count()).select_from(cls).where(cls.deleted == False)  # noqa: E712
        )
        return session.scalars(statement).all(), count

    @classmethod
    def from_id(cls, session, id):
        result = session.scalar(Select(cls).where(cls.id == id, cls.deleted == False)  # noqa: E712
        .options(
                defer(cls.password),
                defer(cls.temp_password),
                defer(cls.temp_password_created_at),
                defer(cls.default_password),
                defer(cls.deleted),
                defer(cls.deleted_at),
                defer(cls.default_password),
            ))
        
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("user", "id"),
                ),
            )
        return result

    @classmethod
    def from_email(cls, session, email, check=False):
        result = session.scalar(
            Select(cls).where(cls.email == email, cls.deleted == False) # noqa: E712
            .options(
                defer(cls.password),
                defer(cls.temp_password),
                defer(cls.temp_password_created_at),
                defer(cls.default_password),
                defer(cls.deleted),
                defer(cls.deleted_at),
                defer(cls.default_password),
            )
        )
        if not result:
            if check:
                return False
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("user", "email"),
                ),
            )
        return result

    @classmethod
    def login(cls, session, user_object, **kwargs):
        is_valid = auth.verify_password(kwargs["password"], user_object.password)
        if is_valid:
            access_token, refresh_token = auth.generate_jwt(email=user_object.email)
            if not user_object.default_password:
                role_id = session.scalars(
                    Select(UserRole.role_id).where(UserRole.user_id == user_object.id)
                ).first()
                role_name = Role.name_from_id(session, role_id)
                user_object.temp_password = None
                user_object.temp_password_created_at = None
                session.add(user_object)
                handle_db_transaction(session)
                logger.info("Login Successful")
                return response_model(
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
            return response_model(
                message="Default password used to login, please change password, use the below provided token to reset password at /password/reset",
                data={"token": auth.generate_otp_jwt(kwargs["email"])},
            )
        logger.error("Invalid Credentials, checking temp password")
        if user_object.temp_password:
            result = auth.verify_password(kwargs["password"], user_object.temp_password)
            if result:
                if (
                    user_object.temp_password_created_at + datetime.timedelta(days=5)
                ).date() > datetime.datetime.now().date():
                    access_token = auth.generate_otp_jwt(kwargs["email"])
                    return response_model(
                        message="Temporary password is used, please use this access token to change password at /reset_password.",
                        data={"token": access_token},
                    )
                raise HTTPException(
                    status_code=401,
                    detail=response_model(
                        message=constants.UNAUTHORIZED,
                        error=constants.TEMP_PASSWORD_ALREADY_USED,
                    ),
                )
        raise HTTPException(
            status_code=401,
            detail=response_model(
                message="Unauthorized", error="Invalid credentials !"
            ),
        )

    @classmethod
    def get_all_role(cls, session, email):
        user_object = cls.from_email(session, email)
        return user_object.role_id.all()


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
    def from_name(cls, session, name):
        result = session.scalar(Select(cls).where(cls.name == name))
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("role", "name"),
                ),
            )
        return result

    @classmethod
    def name_from_id(cls, session, id):
        result = session.scalar(Select(cls.name).where(cls.id == id))
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("role", "id"),
                ),
            )
        return result

    @classmethod
    def role_got_permission(cls, session, permission_required, email_of_user):
        permission_object = Permission.from_scope(session, permission_required)
        permission_id = permission_object.id
        users_all_role = User.get_all_role(session, email_of_user)
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
    def from_scope(cls, session, scope):
        result = session.scalar(Select(cls).where(cls.scope == scope))
        if not result:
            raise HTTPException(
                status_code=404,
                detail=response_model(
                    message=constants.REQUEST_NOT_FOUND,
                    error=constants.request_not_found("permission", "scope"),
                ),
            )
        return result


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
