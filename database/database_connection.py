from sqlalchemy import create_engine, URL
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from utils import constant_messages
from utils.logger import logger
import os

host = os.getenv("HOST")
database = os.getenv("DATABASE")
password = os.getenv("PASSWORD")
user = os.getenv("USER")

url = URL.create(
    username=user,
    password=password,
    host=host,
    database=database,
    drivername="postgresql",
)

engine = create_engine(url, echo=False)
session = Session(bind=engine)


# Base.metadata.create_all(engine)
def try_session_commit(session, delete=False):
    if not delete:
        try:
            session.commit()
            return
        except IntegrityError as e:
            logger.error(print(e._message()))
            session.rollback()
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "error_type": constant_messages.INTEGRITY_ERROR,
                        "error_message": constant_messages.INTEGRITY_ERROR_MESSAGE,
                    }
                },
            )
    else:
        try:
            session.commit()
            return
        except IntegrityError as e:
            logger.error(e._message())
            session.rollback()
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "error_type": constant_messages.DELETION_ERROR,
                        "error_message": constant_messages.deletion_error("device"),
                    }
                },
            )
