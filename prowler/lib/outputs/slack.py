import sys

from slack_sdk import WebClient

from prowler.config.config import aws_logo, azure_logo, gcp_logo, square_logo_img
from prowler.lib.logger import logger


def send_slack_message(token, channel, stats, provider, audit_info):
    try:
        client = WebClient(token=token)
        identity, logo = create_message_identity(provider, audit_info)
        response = client.chat_postMessage(
            username="Prowler",
            icon_url=square_logo_img,
            channel=f"#{channel}",
            blocks=create_message_blocks(identity, logo, stats),
        )
        return response
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def create_message_identity(provider, audit_info):
    try:
        identity = ""
        logo = aws_logo
        if provider == "aws":
            identity = f"AWS Account *{audit_info.audited_account}*"
        elif provider == "gcp":
            identity = f"GCP Projects *{', '.join(audit_info.project_ids)}*"
            logo = gcp_logo
        elif provider == "azure":
            printed_subscriptions = []
            for key, value in audit_info.identity.subscriptions.items():
                intermediate = f"- *{key}: {value}*\n"
                printed_subscriptions.append(intermediate)
            identity = f"Azure Subscriptions:\n{''.join(printed_subscriptions)}"
            logo = azure_logo
        return identity, logo
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def create_message_blocks(identity, logo, stats):
    try:
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": logo,
                    "alt_text": "Provider Logo",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass'] / stats['findings_count'] * 100 , 2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail'] / stats['findings_count'] * 100 , 2)}%)\n ",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:bar_chart: *{stats['resources_count']} Scanned Resources*\n",
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Used parameters: `prowler {' '.join(sys.argv[1:])} `",
                    }
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "Join our Slack Community!"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :slack:"},
                    "url": "https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Feel free to contact us in our repo",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :github:"},
                    "url": "https://github.com/prowler-cloud/prowler",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "See all the things you can do with ProwlerPro",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler Pro"},
                    "url": "https://prowler.pro",
                },
            },
        ]
        return blocks
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
