from sqlalchemy import select
from models import Permission, Role

from database.database_connection import session  

# Define roles and their permissions
role_data = {
    "Admin": ["create_user", "delete_user", "update_user", "view_user", "create_device", "read_device", "update_device", "delete_device"],
    "Device Manager": ["create_device", "read_device", "update_device", "delete_device"],
    "Staff": ["request_device", "view_device"],
    "Viewer": ["view_device"]
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
        print(f'Created Role {role_name}')
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
            print(f'Added permission {scope}')
            # No need to commit here immediately, permissions will be linked later

        # Directly add the permission to the role using the relationship
        if permission not in role.permission_id:
            role.permission_id.append(permission)

# Commit all changes at once
session.commit()

print("Roles and permissions have been added and linked successfully.")