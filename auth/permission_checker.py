from fastapi import Depends, HTTPException
from . import auth
from models import Role


class PermissionChecker:
    def __init__(self, permission_required):
        self.permission_required = permission_required

    def __call__(self, user:dict = Depends(auth.validate_token)):
        # for permission_required in self.permission_required:
        print(self.permission_required)
        # print(Role.get_role_permissions(user['role']))
        is_permitted = Role.role_got_permission(self.permission_required,user['user_identifier'])
        # if permission_required not in Role.get_role_permissions(user['role']):
        if not is_permitted:
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions to access this resource")
        return user

# class ContainPermission:
#     def __init__(self, permissions_required: list):
#         self.permissions_required = permissions_required

#     def __call__(self, user:dict = Depends(auth.validate_token)):
#         for permission_required in self.permissions_required:
#             print(permission_required)
#             # print(Role.get_role_permissions(user['role']))
#             is_permitted = Role.role_got_permission(permission_required,user['user_identifier'])            
#             # if permission_required not in Role.get_role_permissions(user['role']):
#             if not is_permitted:
#                 # raise HTTPException(
#                 #     status_code=403,
#                 #     detail="Not enough permissions to access this resource")
#                 return False
#         return True