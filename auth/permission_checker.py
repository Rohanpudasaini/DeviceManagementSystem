from fastapi import Depends, HTTPException
from utils import constant_messages
from utils.helper_function import error_response
from . import auth
from models import Role


class PermissionChecker:
    def __init__(self, permission_required):
        self.permission_required = permission_required

    def __call__(self, user: dict = Depends(auth.validate_token)):
        is_permitted = Role.role_got_permission(
            self.permission_required, user['user_identifier'])
        if not is_permitted:
            raise HTTPException(
                status_code=403,
                detail=error_response(
                    error={
                        'error_type': constant_messages.FORBIDDEN,
                        'error_message': "Not enough permissions to access this resource"
                    }))
        return user
