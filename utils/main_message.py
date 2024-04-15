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
Vanilla Tech Device Management Team

  
  """
