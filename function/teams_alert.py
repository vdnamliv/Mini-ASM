import requests
import logging
import configparser
import click

def teams_alert_subdomain(domain: str, new_subs: set):
    if not new_subs:
        logging.info(f"No new subdomains for [{domain}] - skipping Teams alert")
        return

    config = configparser.ConfigParser()
    config.read("config.ini")

    try:
        webhook_url  = config.get("teams", "webhook_url")
        mention_id   = config.get("teams", "mention_id")
        mention_name = config.get("teams", "mention_name")
    except Exception as e:
        logging.error(f"Cannot read [teams] config: {e}")
        return

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

    # Nội dung subdomain mới
    subs_text = "\n".join(sorted(new_subs))

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
                            "text": f"[ALERT] New Subdomains for {domain}"
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Found {len(new_subs)} new subdomain(s):\n{subs_text}"
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
