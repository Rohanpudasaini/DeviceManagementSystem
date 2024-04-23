import json
import string
from fastapi import HTTPException
from . import constant_messages
from .logger import logger
from fastapi import Response
import secrets


def check_for_null_or_deleted(object, email='identifier', name='Object'):
    if object or object.deleted:
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message=constant_messages.DELETED_ERROR,
                error=constant_messages.DELETED_ERROR_MESSAGE +
                f' The {object.__class__} was deleted at {object.deleted_at}'
            )
        )
    else:
        raise HTTPException(
            status_code=404,
            detail=error_response(
                message= constant_messages.REQUEST_NOT_FOUND,
                error=constant_messages.request_not_found(name, email)
            
            )
        )


async def log_request(request):
    log_dict = {
        'url_host': request.url.hostname,
        'url_path': request.url.path,
        'url_query': request.url.query,
        'method': request.method,
    }
    logger.info(log_dict, extra=log_dict)


async def log_response(response):
    body = b''.join([section async for section in response.body_iterator])
    logger.info(json.loads(body.decode()))
    return Response(content=body, status_code=response.status_code, headers=dict(response.headers))


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


def error_response(message=None, error=None, data=None):
    return {
        "message": message,
        "error": error,
        "data": data
    }


def normal_response(message=None, data=None, error=None):
    return {
        "message": message,
        "error": error,
        "data": data
    }
