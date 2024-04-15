import os
import smtplib
from email.message import EmailMessage
from utils.main_message import get_temp_password_html, get_temp_password_text

EMAIL = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')


def welcome_mail(email_to_send_to:str,username:str, password:str):
    message = EmailMessage()
    message['Subject'] = "Welcome to Your Device Management System - Account Setup"
    message['From'] = EMAIL
    message['To'] = email_to_send_to
    message.set_content(get_temp_password_text(username, password))
    message.add_alternative(get_temp_password_html(username,password), subtype='html')


    with smtplib.SMTP_SSL('smtp.gmail.com',465) as smtp:
        smtp.login(EMAIL,PASSWORD)
        smtp.send_message(message)
