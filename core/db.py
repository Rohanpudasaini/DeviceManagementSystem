from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from psycopg2.errors import NotNullViolation
from fastapi import HTTPException
from core import constants
from core.logger import logger
from sqlalchemy.orm import DeclarativeBase

from core.utils import response_model
from core.config import config

engine = create_engine(config.database_url, pool_size=15, echo=False)
SessionLocal = sessionmaker(autocommit=False, bind=engine, autoflush=False)


def get_session():
    try:
        session = SessionLocal()
        return session
    except Exception:
        session.rollback()
    finally:
        session.close()


class Base(DeclarativeBase):
    pass


# Base.metadata.create_all(engine)
def handle_db_transaction(session: Session):
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
                error=constants.INTEGRITY_ERROR_MESSAGE,
            ),
        )
    except NotNullViolation as e:
        logger.error(print(e._message()))
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail=response_model(
                message=constants.INTEGRITY_ERROR,
                error=constants.NULL_VALUE_ERROR,
            ),
        )
    except Exception as e:
        logger.error(print(e))
        session.rollback()
        raise HTTPException(
            status_code=500,
            detail=response_model(
                message=constants.INTERNAL_ERROR, error=constants.internal_error(str(e))
            ),
        )
