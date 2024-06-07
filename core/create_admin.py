from apps.user.models import User
from core.db import get_session
from apps.device.models import Device  # noqa: F401

session = get_session()
admin = User()
password, name, _= admin.add(
    session=session,
    email="admin1@dms.com",
    first_name = "Admin",
    last_name = "Test",
    phone_no = "Test",
    address = "Test",
    city = "Test",
    postal_code = "Test",
    role="admin",
)
print(f"Hello {name}, your temp password is {password}")
