# Device Management System Using FastAPI

<p align="center">
  <a><img src="images/dms_logo1.png" alt="Device Management System" ></a>
</p>
<p align="center">
  <em>Streamlined device management system to facilitate device tracking and control with FastAPI</em>
</p>

This is a robust device management system API crafted using FastAPI for handling endpoints, SQLAlchemy as the ORM, and PostgreSQL for the backend database.

## How to run this code?

1. Clone the repository and navigate to the directory

   Start by cloning the repository to your desired location. If you are using a terminal, navigate to the directory where you want to store the project and execute the following commands:

   ```bash
   git clone https://github.com/Rohanpudasaini/DeviceManagementSystem.git
   ```

   This will create a directory named `device_management_system_fastAPI`. Next, change into this directory:

   ```bash
   cd device_management_system_fastAPI
   ```

2. Create a `.env` file

   Set up your environment variables in a `.env` file using the following format:

   ```bash
   HOST=database_host
   DATABASE=database_name
   USER=database_username
   PASSWORD=database_password
   SECRET_ACCESS=AccessToken_secret_key
   ALGORITHM=Token_algorithm
   SECRET_REFRESH=RefreshToken_secret_key
   OTP_SECRET=secret_for_otp
   EMAIL=email_to_send_notification
   EMAIL_PASSWORD=email_app_password
   ```

3. Install dependencies

   Install the required Python packages with pip:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application

   Launch the application using Uvicorn with the following command:

   ```bash
   uvicorn main:app --reload
   ```

   The `--reload` flag will automatically reload the application whenever you make changes to the code. You can also use `--host 0.0.0.0` to make the API accessible on your local network.

## API Documentation

   Visit `localhost/api/v1/docs` to access the Swagger UI, where you can view the API documentation and test the endpoints directly from your browser.

## Authentication and Authorization

   The system utilizes JWT for handling access and refresh tokens. To obtain these tokens, log in through the `/login` endpoint using a POST request with your credentials in the body. Access tokens expire in 20 minutes, whereas refresh tokens last approximately one week. Use the `/refresh` endpoint to renew your access token using your saved refresh token.

## Accessing Protected Routes

   To access protected routes, include the JWT access token as a bearer token in the Authorization header of your requests. Here is an example using curl:

   ```bash
   curl -X 'GET' \
   'http://localhost:8000/api/v1/device?page_number=1&page_size=20' \
   -H 'accept: application/json' \
   -H 'Authorization: Bearer your_access_token_here'
   ```

## Conclusion

   This FastAPI project is designed to introduce fundamental concepts of device management and API development with modern Python frameworks. While functional for basic operations, the project is continuously evolving to incorporate more features.
