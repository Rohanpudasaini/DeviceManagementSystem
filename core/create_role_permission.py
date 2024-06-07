from sqlalchemy import select
from apps.device.models import Device  # noqa: F401

from apps.user.models import Permission, Role
from core.db import get_session

# Assuming session is already created from Session()

session = get_session()
# Define roles and their specific permissions
role_data = {
    "admin": [
        "create_user",
        "delete_user",
        "update_user",
        "view_user",
        "manage_devices",
        "create_device",
        "read_device",
        "update_device",
        "delete_device",
    ],
    "device_manager": [
        "create_device",
        "read_device",
        "update_device",
        "delete_device",
    ],
    "staff": ["request_device", "view_device"],
    "viewer": ["view_device"],
}

for role_name, permissions in role_data.items():
    # Create or find role
    role = session.execute(
        select(Role).where(Role.name == role_name)
    ).scalar_one_or_none()

    # If role does not exist, create it
    if role is None:
        role = Role(name=role_name)
        session.add(role)
        # No need to commit here immediately unless needed for ID generation

    # Check and create permissions, and link them directly to the role
    for scope in permissions:
        # Check if permission already exists
        permission = session.execute(
            select(Permission).where(Permission.scope == scope)
        ).scalar_one_or_none()

        # If permission does not exist, create it
        if permission is None:
            permission = Permission(scope=scope)
            session.add(permission)
            session.commit()

        if permission not in role.permission_id:
            role.permission_id.append(permission)

# Commit all changes at once
session.commit()

print("Roles and permissions have been added and linked successfully.")
