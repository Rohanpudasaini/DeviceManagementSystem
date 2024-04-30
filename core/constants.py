INTERNAL_ERROR = "Internal Error"
TOKEN_VERIFICATION_FAILED = "Couldn't Verify Token, Invalid or expired token"
INVALID_TOKEN_SCHEME = "Invalid Token Scheme!"
NO_TOKEN_IN_HEADER = "No token available!"
REQUEST_NOT_FOUND = "Request Not Found"
INVALID_REQUEST = "Invalid Request"
UNAUTHORIZED = "Authorization Error"
UNAUTHORIZED_MESSAGE = "Incorrect credentials"
TOKEN_ERROR = "Expired Or Invalid Token"
FORBIDDEN = "Forbidden"
FORBIDDEN_MESSAGE = "Not enough permissions to access this resource"
NO_CONTENT = "No content"
NO_CONTENT_MESSAGE = "No Content Found"
INSUFFICIENT_RESOURCES = "Insufficient Resources"
BAD_REQUEST = "Bad Request"
BAD_REQUEST_MESSAGE = "The password do not match"
INTEGRITY_ERROR = "IntegrityError"
INTEGRITY_ERROR_MESSAGE = "Can't compute your request. Duplicate value"
DELETION_ERROR = "Can't Delete"
DELETED_ERROR = "Object Deleted"
DELETED_ERROR_MESSAGE = "The Object you have requested for is deleted, please select other."
EXPIRED_TOKEN = "Expired token"
SAME_PASSWORD = "Same Password"
CONFLICT = "Conflict"
DEVICE_ALREADY_IN_USED = "The user have some devices assigned to them, can't delete the user"
SAME_PASSWORD_MESSAGE = "New password same as old password"
MAINTENANCE = "Device In Maintenance"
MAINTENANCE_MESSAGE = "The device you have request for is in maintenance"
TEMP_PASSWORD_ALREADY_USED = "The temp password is already expired, please request for another one. !"
DUPLICATE_REQUEST = "The request you are making is already present in our end, please wait for the mail from our admin stating the request result."

def internal_error(error_message):
    return f"An unexpected error occurred. Please reach out to us with this message: {error_message}"

def deletion_error(name: str):
    return f"Can't delete this {name}, it might be already be in use or in repair."


def invalid_length(name: str, length: int):
    return f"The {name} must be of {length} length"


def request_not_found(name: str, distinguisher: str):
    return f"No {name} with that {distinguisher}"


def bad_request(name: str, distinguisher: str, already_issued: bool = False):
    if not already_issued:
        return f"{name} with that {distinguisher} already exist"
    return f"You have already issued this {name}"


def insufficient_resources(name: str):
    return f"The requested {name} is currently assigned to some other user, please check again after some days."

def no_device_associated(name:str):
    return f"No device is associated with the {name}"