import logging
import sys
import os

logger = logging.getLogger("FastAPI Log")

formatter = logging.Formatter(fmt="%(asctime)s - %(levelname)s - %(message)s")

stream_handler = logging.StreamHandler(sys.stdout)
paths = "log/app.log"
if os.path.exists(paths):
    file_handler = logging.FileHandler("log/app.log")
else:
    os.mkdir("log")
    file = open("log/app.log", "a")
    file.close()
    file_handler = logging.FileHandler("log/app.log")

stream_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.handlers = [stream_handler, file_handler]

logger.setLevel(logging.INFO)
