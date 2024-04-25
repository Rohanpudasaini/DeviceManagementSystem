from fastapi import FastAPI
from apps.auth.routers import router as auth_router
from apps.user.routers import router as user_router
from apps.device.routers import router as device_router


description = """
Device Management API helps you maintain your devices and their users. 🚀

"""


app = FastAPI(
    title="DeviceManagementSystem",
    description=description,
    summary="All your Device related stuff.",
    version="1.0.1",
    root_path="/api/v1",
)


@app.get("/", tags=["Home"])
async def home():
    return "Welcome Home"


app.include_router(auth_router)
app.include_router(user_router)
app.include_router(device_router)
