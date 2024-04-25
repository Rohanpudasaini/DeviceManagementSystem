from pydantic.v1 import BaseSettings
from functools import lru_cache
from core.logger import logger
from pydantic import AnyUrl


class Config(BaseSettings):
    database_url: AnyUrl | str
    secret_access: str
    secret_refresh: str
    algorithm: str
    otp_secret: str
    email: str
    email_password: str

    class Config:
        env_file = ".env"


@lru_cache
def get_config():
    logger.info("Config loaded from environment variables")
    return Config()


config = get_config()
