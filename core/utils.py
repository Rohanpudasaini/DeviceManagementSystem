import string
from core.logger import logger
import secrets


async def log_request(request):
    log_dict = {
        'url_host': request.url.hostname,
        'url_path': request.url.path,
        'url_query': request.url.query,
        'method': request.method,
    }
    logger.info(log_dict, extra=log_dict)



def generate_password(length):
    letters = string.ascii_letters
    digits = string.digits
    special_chars = "$-_.+!*'(),"
    selection_list = letters + digits + special_chars
    password = ''
    for i in range(length):
        password += ''.join(secrets.choice(selection_list))
    password = password.replace('"', "'")
    return password


def response_model(message=None, data=None, error=None):
    return {
        "message": message,
        "error": error,
        "data": data
    }
