import logging
import sys

logger = logging.getLogger("FastAPI Log")

formater = logging.Formatter(
    fmt="%(asctime)s - %(levelname)s - %(message)s"
)

stream_handler = logging.StreamHandler(sys.stdout)
file_handler = logging.FileHandler('log/app.log')

stream_handler.setFormatter(formater)
file_handler.setFormatter(formater)

logger.handlers = [stream_handler, file_handler]

logger.setLevel(logging.INFO)
