from fastapi import Depends, HTTPException
from core import constants
from core.utils import error_response
from . import auth
from apps.device.models import Role


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
                    message = constants.FORBIDDEN,
                    error="Not enough permissions to access this resource"
                    ))
        return user
