from fastapi import FastAPI

description = """
Device Management API helps you maintain your devices and their users. 🚀

"""


api_v1 = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All your Device related stuff.",
    version="1.0.1",
)


@api_v1.get("/", tags=["Home"])
async def home():
    return "Welcome Home"


