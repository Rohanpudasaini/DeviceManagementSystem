from fastapi import Depends, HTTPException
from core import constants
from core.db import get_session
from core.utils import response_model
from . import auth
from apps.user.models import Role


class PermissionChecker:
    def __init__(self, permission_required):
        self.permission_required = permission_required

    def __call__(
        self, user: dict = Depends(auth.validate_token), session=Depends(get_session)
    ):
        is_permitted = Role.role_got_permission(
            session, self.permission_required, user["user_identifier"]
        )
        if not is_permitted:
            raise HTTPException(
                status_code=403,
                detail=response_model(
                    message=constants.FORBIDDEN,
                    error="Not enough permissions to access this resource",
                ),
            )
        return user
