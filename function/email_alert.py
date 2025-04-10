# file: function/email_alert.py

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import configparser
import os

config = configparser.ConfigParser()
config.read("config.ini")

ALERT_EMAIL   = config.get("email", "alert_email")
SMTP_SERVER   = config.get("email", "smtp_server")
SMTP_PORT     = int(config.get("email", "smtp_port"))
SMTP_USER     = config.get("email", "smtp_user")
SMTP_PASSWORD = config.get("email", "smtp_password")

def send_email_alert(subject, message):
    """
    Gửi email sử dụng SMTP (thông tin lấy từ config.ini).
    """
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"]   = ALERT_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())

        logging.info(f"Alert email sent to {ALERT_EMAIL}.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def email_alert_message(domain: str, message: str):
    """
    Gửi email alert với nội dung `message` (có thể gộp cả subdomain mới + expired).
    Nếu `message` rỗng, không gửi.
    """
    if not message.strip():
        logging.info(f"No message for [{domain}] - skipping email alert")
        return

    subject = f"[ALERT] Subdomain Report for [{domain}]"
    send_email_alert(subject, message)
