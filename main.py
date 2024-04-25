from fastapi import APIRouter, FastAPI
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
    docs_url="/docs"
)

api_v1 = APIRouter()

@api_v1.get("/", tags=["Home"])
async def home():
    return "Welcome Home"

api_v1.include_router(user_router)
api_v1.include_router(device_router)
app.include_router(api_v1)

