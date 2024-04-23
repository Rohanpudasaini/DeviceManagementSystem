INTERNAL_ERROR = "Internal Error"
INTERNAL_ERROR_MESSAGE = "An unexpected error occurred. Please try again later."
TOKEN_VERIFICATION_FAILED = "Couldn't Verify Token, Invalid or expired token"
INVALID_TOKEN_SCHEME = "Invalid Token Scheme!"
NO_TOKEN_IN_HEADER = "No token available!"
REQUEST_NOT_FOUND = "Request Not Found"
MAGAZINE_REQUEST_NOT_FOUND_MESSAGE = "The Magazine with that ISSN number not found"
PUBLISHER_REQUEST_NOT_FOUND_MESSAGE = "No publisher with that id"
GENRE_REQUEST_NOT_FOUND_MESSAGE = "No genre with that id"
INVALID_REQUEST = "Invalid Request"
UNAUTHORIZED = "Authorization Error"
UNAUTHORIZED_MESSAGE = "Incorrect credentials"
TOKEN_ERROR = "Expired Or Invalid Token"
FORBIDDEN = "Forbidden"
NO_CONTENT = "No content"
NO_CONTENT_MESSAGE = "No Content Found"
INSUFFICIENT_RESOURCES = "Insufficient Resources"
BAD_REQUEST = "Bad Request"
INTEGRITY_ERROR = "IntegrityError"
INTEGRITY_ERROR_MESSAGE = "Can't compute your request. Duplicate value"
DELETION_ERROR = "Can't Delete"
DELETED_ERROR = "Object Deleted"
DELETED_ERROR_MESSAGE = (
    "The Object you have requested for is deleted, please select other."
)
EXPIRED_TOKEN = "Expired token"


def deletion_error(name: str):
    return f"Can't delete this {name}, it might be already be in use or in repair."


def invalid_length(name: str, length: int):
    return f"The {name} must be of {length} length"


def request_not_found(name: str, distinguisher: str):
    return f"No {name} with that {distinguisher}"


def bad_request(name: str, distinguisher: str, already_issued: bool = False):
    if not already_issued:
        return f"{name} with that {distinguisher} already exsist"
    return f"You have already issued this {name}"


def insufficient_resources(name: str):
    return f"The requested {name} is currently assigned to some other user, please check again after some days."
