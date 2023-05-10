import sys
from unittest import mock

from prowler.config.config import aws_logo, azure_logo, gcp_logo
from prowler.lib.outputs.slack import (
    create_message_blocks,
    create_message_identity,
    send_slack_message,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info

AWS_ACCOUNT_ID = "123456789012"


def mock_create_message_blocks(*_):
    return [{}]


def mock_create_message_identity(*_):
    return "", ""


class Test_Slack_Integration:
    def test_create_message_identity(self):
        aws_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        gcp_audit_info = GCP_Audit_Info(
            credentials=None,
            project_id="test-project",
            audit_resources=None,
            audit_metadata=None,
        )
        azure_audit_info = Azure_Audit_Info(
            credentials=None,
            identity=Azure_Identity_Info(
                identity_id="",
                identity_type="",
                tenant_ids=[],
                domain="",
                subscriptions={
                    "subscription 1": "qwerty",
                    "subscription 2": "asdfg",
                },
            ),
            audit_resources=None,
            audit_metadata=None,
        )
        assert create_message_identity("aws", aws_audit_info) == (
            f"AWS Account *{aws_audit_info.audited_account}*",
            aws_logo,
        )
        assert create_message_identity("gcp", gcp_audit_info) == (
            f"GCP Project *{gcp_audit_info.project_id}*",
            gcp_logo,
        )
        assert create_message_identity("azure", azure_audit_info) == (
            "Azure Subscriptions:\n- *subscription 1: qwerty*\n- *subscription 2: asdfg*\n",
            azure_logo,
        )

    def test_create_message_blocks(self):
        aws_identity = f"AWS Account *{AWS_ACCOUNT_ID}*"
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
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {aws_identity} with a total of *{stats['findings_count']}* findings.",
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
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
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
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {azure_identity} with a total of *{stats['findings_count']}* findings.",
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
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
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
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {gcp_identity} with a total of *{stats['findings_count']}* findings.",
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
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
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
            response = send_slack_message(
                "test-token", "test-channel", {}, "provider", {}
            )
            assert response == mocked_slack_response
