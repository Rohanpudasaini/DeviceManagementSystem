from sqlalchemy import create_engine, URL
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from core import constants
from core.logger import logger
import os
from sqlalchemy.orm import DeclarativeBase

from core.utils import response_model

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


class Base(DeclarativeBase):
    pass

# Base.metadata.create_all(engine)
def handle_db_transaction(session):
    try:
        session.commit()
        return
    except IntegrityError as e:
        logger.error(print(e._message()))
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail=response_model(
                    message=constants.INTEGRITY_ERROR,
                    error =constants.INTEGRITY_ERROR_MESSAGE,
            )
        )
    except Exception as e:
        logger.error(print(e))
        session.rollback()
        raise HTTPException(
            status_code= 500,
            detail= response_model(
                message= constants.INTERNAL_ERROR,
                error= constants.internal_error(str(e))
            )
        )
    
