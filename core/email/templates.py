def get_temp_password_html(username: str, temp_password: str):
    html_message = """\
    <!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Device Management System - Temporary Password</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f0f0f0;
            }}
            .header {{
                background-color: #004d99;
                color: #ffffff;
                padding: 20px;
                text-align: center;
            }}
            .content {{
                padding: 20px;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to Our Device Management System</h1>
        </div>
        <div class="content">
            <h2>Dear {username}, Your Account Has Been Created Successfully</h2>
            <p>
                A temporary password has been created for your account. Please change this password as soon as you log in.
            </p>
            <p>
                <strong>Temporary Password: {temp_password}</strong>
            </p>
            <p>
                To change your password, please log into your account, go to your profile, and select "Change Password".
            </p>
            <p>
                Through our system, you can browse available devices, request new devices, and manage your device bookings. If you need any help, our support team is here to assist you.
            </p>
            <p>Explore our services and enhance your workplace experience!</p>
        </div>
    </body>
</html>

    """
    return html_message.format(username=username, temp_password=temp_password)


def get_temp_password_text(username: str, temp_password: str):
    return f"""
Subject: Welcome to Your Device Management System - Account Setup

Dear {username},

Welcome to Our Device Management System! Your account has been successfully created.

Here is your temporary password: {temp_password}

For your security, please change this password as soon as you log in for the first time. Log into your account, navigate to your profile, and select "Change Password" to update it.

What you can do with our system:
- Browse the catalog of available devices.
- Request new devices as per your requirements.
- Manage your current device bookings and requests.

Our device management system is designed to streamline how our office handles device allocation and management, ensuring you have the tools you need when you need them.

If you encounter any issues or have questions, please reach out to our support team for assistance.

Thank you for joining, and we hope you find our system useful for managing your device needs efficiently!

Best Regards,
Device Management Team

"""


def get_reset_link_html(username: str, password: str):
    html_message = """\
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Notification</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 600px;
            margin: auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .alert {{
            color: #007bff; /* Bootstrap blue */
            font-size: 18px;
        }}
        .temp-password {{
            color: #dc3545; /* Bootstrap red */
            font-size: 16px;
            margin-top: 20px;
        }}
        .instructions {{
            margin-top: 20px;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Password Reset Requested</h1>
        <p class="alert">Dear {username}, A request to reset your password has been processed.</p>
        <p class="temp-password">Temporary Password: <strong>{password}</strong></p>
        <p>This password is valid for 5 days only. Please log in and change your password as soon as possible.</p>
        <div class="instructions">
            <p>Use this temporary password to log in to your account and update your password through your account settings.</p>
            <p>If you did not request a password reset, please contact our support team immediately to secure your account.</p>
        </div>
    </div>
</body>
</html>
    """
    return html_message.format(username=username, password=password)


def get_reset_link_text(username: str, password: str):
    return f"""
Subject: Password Reset Instructions

Hello {username},

You recently requested to reset your password for your account. Below is the one-time password (OTP) you need to proceed with resetting your password. This OTP is valid for only 5 days:

OTP: {password}

Please enter this OTP on the password reset page to create a new password. If you did not request a password reset, please ignore this email or contact our support if you believe this is an unauthorized attempt to access your account.

Thank you for using our system!

Best regards,
Device Management Support Team

"""

def device_confirmation_html(user_name, device_name, device_model, end_date, start_date):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Allocation Confirmation</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 600px;
            margin: auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .header {{
            color: #28a745; /* Bootstrap green */
            margin-bottom: 20px;
        }}
        .details {{
            text-align: left;
            margin-top: 20px;
            font-size: 16px;
        }}
        .highlight {{
            color: #007bff; /* Bootstrap blue */
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">Device Allocation Confirmation</h1>
        <p>Dear <span class="highlight">{user_name}</span>,</p>
        <p>We are pleased to inform you that your request for the device has been accepted. The details of the device allocation are as follows:</p>
        <div class="details">
            <p><strong>Device Name:</strong> <span class="highlight">{device_name}</span></p>
            <p><strong>Device Model:</strong> <span class="highlight">{device_model}</span></p>
            <p><strong>Allocation Period:</strong> <span class="highlight">{start_date}</span> to <span class="highlight">{end_date}</span></p>
        </div>
        <p>Please ensure to collect the device from the IT department and return it by the end of the allocation period. Should you have any questions or require further assistance, please do not hesitate to contact the IT department.</p>
        <p>Thank you for using our Device Management System!</p>
    </div>
</body>
</html>


"""


def device_confirmation_text(user_name, device_name, device_model, end_date, start_date):
    return f"""
Dear {user_name},

We are pleased to inform you that your request for the device has been accepted. Below are the details of your device allocation:

- Device Name: {device_name}
- Device Model: {device_model}
- Allocation Period: {start_date} to {end_date}

Please ensure to collect the device from the IT department and return it by the end of the allocation period. If you have any questions or need further assistance, please do not hesitate to contact the IT department.

Thank you for using our Device Management System!

Best regards,
"""

def device_rejection_html(user_name, device_name, device_model, request_date):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Allocation Rejection</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 600px;
            margin: auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .header {{
            color: #dc3545; /* Bootstrap red */
            margin-bottom: 20px;
        }}
        .details {{
            text-align: left;
            margin-top: 20px;
            font-size: 16px;
        }}
        .highlight {{
            color: #007bff; /* Bootstrap blue */
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">Device Allocation Rejection</h1>
        <p>Dear <span class="highlight">{user_name}</span>,</p>
        <p>We regret to inform you that your request for the device has been rejected. The details of your request are as follows:</p>
        <div class="details">
            <p><strong>Device Name:</strong> <span class="highlight">{device_name}</span></p>
            <p><strong>Device Model:</strong> <span class="highlight">{device_model}</span></p>
            <p><strong>Request Date:</strong> <span class="highlight">{request_date}</span></p>
        </div>
        <p>This decision may be due to a number of factors such as limited availability or eligibility requirements not being met. Please contact the IT department if you believe this decision requires further review or to discuss alternative solutions.</p>
        <p>Thank you for understanding and for using our Device Management System.</p>
    </div>
</body>
</html>


"""


def device_rejection_text(user_name, device_name, device_model, request_date):
    return f"""
Dear {user_name},

We regret to inform you that your request for the device has been rejected. Below are the details of your request:

- Device Name: {device_name}
- Device Model: {device_model}
- Request Date: {request_date}

This decision may be due to a number of factors such as limited availability or eligibility requirements not being met. Please contact the IT department if you believe this decision requires further review or to discuss alternative solutions.

Thank you for understanding and for using our Device Management System.

Best regards,
"""
