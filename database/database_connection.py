from sqlalchemy import create_engine, URL 
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from utils import constant_messages
from utils.logger import logger
import os

host = os.getenv('host')
database= os.getenv('database')
password = os.getenv('password')
user = os.getenv('user')

url = URL.create(
    username=user,
    password=password,
    host=host,
    database=database,
    drivername='postgresql'
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
            raise HTTPException(status_code=409,
                                detail={
                                    "error": {
                                        "error_type": constant_messages.INTEGERITYERROR,
                                        "error_message": constant_messages.INTEGERITYERROR_MESSAGE
                                    }
                                })
    else:
        try:
            session.commit()
            return
        except IntegrityError as e:
            logger.error(e._message())
            session.rollback()
            raise HTTPException(status_code=409,
                                detail={
                                    "error": {
                                        "error_type": constant_messages.DELETIONERROR,
                                        "error_message": constant_messages.deletionerror('device')
                                    }
                                })