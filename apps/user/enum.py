from enum import Enum

class RoleType(Enum):
    admin = "admin"
    device_manager = "device_manager"
    staff = "staff"
    viewer = "viewer"


class Designation(Enum):
    manager = "manager"
    developer = "developer"
    hr = "hr"
    it_support = "it_support"
    ceo = "ceo"
    viewer = "viewer"