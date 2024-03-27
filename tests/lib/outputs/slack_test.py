import sys
from unittest import mock

from prowler.config.config import aws_logo, azure_logo, gcp_logo
from prowler.lib.outputs.slack import (
    create_message_blocks,
    create_message_identity,
    send_slack_message,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, set_mocked_aws_provider
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)
from tests.providers.gcp.gcp_fixtures import set_mocked_gcp_provider


def mock_create_message_blocks(*_):
    return [{}]


def mock_create_message_identity(*_):
    return "", ""


class TestSlackIntegration:
    def test_create_message_identity_aws(self):
        aws_provider = set_mocked_aws_provider()

        assert create_message_identity(aws_provider) == (
            f"AWS Account *{aws_provider.identity.account}*",
            aws_logo,
        )

    def test_create_message_identity_azure(self):
        azure_provider = set_mocked_azure_provider()

        assert create_message_identity(azure_provider) == (
            f"Azure Subscriptions:\n- *{AZURE_SUBSCRIPTION_ID}: {AZURE_SUBSCRIPTION_NAME}*\n",
            azure_logo,
        )

    def test_create_message_identity_gcp(self):
        gcp_provider = set_mocked_gcp_provider(
            project_ids=["test-project1", "test-project2"],
        )

        assert create_message_identity(gcp_provider) == (
            f"GCP Projects *{', '.join(gcp_provider.project_ids)}*",
            gcp_logo,
        )

    def test_create_message_blocks(self):
        aws_identity = f"AWS Account *{AWS_ACCOUNT_NUMBER}*"
        azure_identity = "Azure Subscriptions:\n- *subscription 1: qwerty*\n- *subscription 2: asdfg*\n"
        gcp_identity = "GCP Project *gcp-project*"
        stats = {}
        stats["total_pass"] = 12
        stats["total_fail"] = 10
        stats["resources_count"] = 20
        stats["findings_count"] = 22
        assert create_message_blocks(aws_identity, aws_logo, stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {aws_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": aws_logo,
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
        assert create_message_blocks(azure_identity, azure_logo, stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {azure_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": azure_logo,
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
        assert create_message_blocks(gcp_identity, gcp_logo, stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {gcp_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": gcp_logo,
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

    def test_send_slack_message(self):
        mocked_slack_response = {
            "ok": True,
            "channel": "XXXXXXXXXX",
            "ts": "1683623300.083429",
            "message": {
                "type": "message",
                "subtype": "bot_message",
                "text": "",
                "ts": "1683623300.083429",
                "username": "Prowler",
                "icons": {},
                "bot_id": "B055L25CVFH",
                "app_id": "A055U03H2QN",
                "blocks": [],
            },
        }

        mocked_web_client = mock.MagicMock
        mocked_web_client.chat_postMessage = mock.Mock(
            return_value=mocked_slack_response
        )
        with mock.patch(
            "prowler.lib.outputs.slack.create_message_blocks",
            new=mock_create_message_blocks,
        ), mock.patch(
            "prowler.lib.outputs.slack.create_message_identity",
            new=mock_create_message_identity,
        ), mock.patch(
            "prowler.lib.outputs.slack.WebClient", new=mocked_web_client
        ):
            response = send_slack_message("test-token", "test-channel", {}, "provider")
            assert response == mocked_slack_response
