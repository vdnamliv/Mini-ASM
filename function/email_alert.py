import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import configparser
import os

config = configparser.ConfigParser()
config.read("config.ini")

ALERT_EMAIL = config.get("email", "alert_email")
SMTP_SERVER = config.get("email", "smtp_server")
SMTP_PORT = int(config.get("email", "smtp_port"))
SMTP_USER = config.get("email", "smtp_user")
SMTP_PASSWORD = config.get("email", "smtp_password")

def send_email_alert(subject, message):
    """Send an alert email using smtplib."""
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())

        logging.info(f"Alert email sent to {ALERT_EMAIL}.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def email_alert_subdomain(domain: str, new_subs: set):

    if new_subs:
        subject = f"[ALERT] Found {len(new_subs)} new subdomain(s) for [{domain}]"
        message = "New subdomains:\n" + "\n".join(new_subs)
        send_email_alert(subject, message)
    else:
        logging.info(f"No new subdomains for [{domain}] - skipping email alert")

