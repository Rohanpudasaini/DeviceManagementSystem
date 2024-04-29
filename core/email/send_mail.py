import datetime
import smtplib
from email.message import EmailMessage
from core.email.templates import (
    device_confirmation_html,
    device_confirmation_text,
    device_rejection_html,
    device_rejection_text,
    get_reset_link_html,
    get_reset_link_text,
    get_temp_password_html,
    get_temp_password_text,
)
from core.config import config

email = config.email
email_password = config.email_password


def welcome_mail(email_to_send_to: str, username: str, password: str):
    message = EmailMessage()
    message["Subject"] = "Welcome to Your Device Management System - Account Setup"
    message["From"] = email
    message["To"] = email_to_send_to
    message.set_content(get_temp_password_text(username, password))
    message.add_alternative(get_temp_password_html(username, password), subtype="html")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(email, email_password)
        smtp.send_message(message)


def reset_mail(email_to_send_to: str, username: str, password: str):
    message = EmailMessage()
    message["Subject"] = "Password Reset Request"
    message["From"] = email
    message["To"] = email_to_send_to
    message.set_content(get_reset_link_text(username, password=password))
    message.add_alternative(
        get_reset_link_html(username, password=password), subtype="html"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(email, email_password)
        smtp.send_message(message)
        

def confirmation_mail(email_to_send_to:str, username:str, device_name:str, device_model:str, end_date):
    message = EmailMessage()
    message["Subject"] = "Device Allocation Confirmation"
    message["From"] = email
    message["To"] = email_to_send_to
    message.set_content(device_confirmation_text(username, device_name=device_name, device_model=device_model, end_date= end_date, start_date=datetime.datetime.now().date()))
    message.add_alternative(
        device_confirmation_html(username, device_name=device_name, device_model=device_model, end_date= end_date, start_date=datetime.datetime.now().date()), subtype="html"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(email, email_password)
        smtp.send_message(message)
        

def rejection_mail(email_to_send_to:str, username:str, device_name:str, device_model:str, requested_date):
    message = EmailMessage()
    message["Subject"] = "Device Allocation Rejection"
    message["From"] = email
    message["To"] = email_to_send_to
    message.set_content(device_rejection_text(username, device_name=device_name, device_model=device_model, request_date= requested_date))
    message.add_alternative(
        device_rejection_html(username, device_name=device_name, device_model=device_model, request_date= requested_date), subtype="html"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(email, email_password)
        smtp.send_message(message)
