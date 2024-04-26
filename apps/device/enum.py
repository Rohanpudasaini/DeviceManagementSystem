from enum import Enum

class Purpose(Enum):
    REPAIR = "repair"
    UPGRADE = "upgrade"
    EXCHANGE = "exchange"


class DeviceType(Enum):
    LAPTOP = "laptop"
    TABLET = "tablet"
    PHONE = "phone"
    DESKTOP = "desktop"


class DeviceStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class RequestStatus(Enum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"