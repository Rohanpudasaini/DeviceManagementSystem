from ..models import Base
from database_connection import engine

Base.metadata.create_all(bind=engine)