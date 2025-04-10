import requests
import logging
import configparser
import click

def teams_alert_message(domain: str, message: str):
    """
    Gửi Teams alert với nội dung `message` (một chuỗi duy nhất).
    Bạn có thể gộp cả subdomain mới lẫn expired subdomain vào message.

    Args:
        domain (str): Tên domain đang monitor.
        message (str): Nội dung cần gửi lên Teams.
                       Ví dụ: "Found 2 new subdomains:\n 1. abc\n 2. xyz\n\n2 subdomains expired:\n ...
    """
    # Đọc config để lấy webhook_url, mention_id, mention_name
    config = configparser.ConfigParser()
    config.read("config.ini")

    try:
        webhook_url  = config.get("teams", "webhook_url")
        mention_id   = config.get("teams", "mention_id")
        mention_name = config.get("teams", "mention_name")
    except Exception as e:
        logging.error(f"Cannot read [teams] config: {e}")
        return

    # Nếu message rỗng, ta có thể bỏ qua hoặc gửi tin "No updates"
    if not message.strip():
        logging.info(f"No message to send for domain [{domain}] - skipping Teams alert.")
        return

    # Xây dựng phần mention
    mentions = [
        {
            "type": "mention",
            "text": f"<at>{mention_name}</at>",
            "mentioned": {
                "id": mention_id,
                "name": mention_name
            }
        }
    ]

    # Build Adaptive Card cho MS Teams
    headers = {"Content-Type": "application/json"}
    body = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "text": f"[ALERT] Subdomain Report for {domain}"
                        },
                        {
                            "type": "TextBlock",
                            "text": f"{message}"
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Hi <at>{mention_name}</at>"
                        }
                    ],
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.0",
                    "msteams": {
                        "entities": mentions
                    }
                }
            }
        ]
    }

    # Gửi request
    try:
        response = requests.post(webhook_url, headers=headers, json=body)
        if 200 <= response.status_code < 300:
            logging.info(f"Teams alert sent successfully. Status code: {response.status_code}")
        else:
            logging.error(f"Failed to send Teams alert. Status code: {response.status_code}, response={response.text}")
    except requests.RequestException as e:
        logging.error(f"Error sending Teams alert: {e}")
