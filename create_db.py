from models import Base

# from models import Base
from database.database_connection import engine

Base.metadata.create_all(bind=engine)
