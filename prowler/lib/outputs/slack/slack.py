import os
from typing import Any

from slack_sdk import WebClient
from slack_sdk.web.base_client import SlackResponse

from prowler.config.config import aws_logo, azure_logo, gcp_logo, square_logo_img
from prowler.lib.logger import logger
from prowler.lib.outputs.slack.exceptions.exceptions import (
    SlackChannelNotFound,
    SlackClientError,
    SlackNoCredentialsError,
)
from prowler.providers.common.models import Connection


class Slack:
    _provider: Any
    _token: str
    _channel: str

    def __init__(self, token: str, channel: str, provider: Any) -> "Slack":
        self._token = token
        self._channel = channel
        self._provider = provider

    @property
    def token(self):
        return self._token

    @property
    def channel(self):
        return self._channel

    def send(self, stats: dict, args: str) -> SlackResponse:
        """
        Sends the findings to Slack.

        Args:
            stats (dict): A dictionary containing audit statistics.
            args (str): Command line arguments used for the audit.

        Returns:
            SlackResponse: Slack response if successful, error object if an exception occurs.
        """
        try:
            client = WebClient(token=self.token)
            identity, logo = self.__create_message_identity__(self._provider)
            response = client.chat_postMessage(
                username="Prowler",
                icon_url=square_logo_img,
                channel=f"#{self.channel}",
                text="Prowler Scan Summary",
                blocks=self.__create_message_blocks__(identity, logo, stats, args),
            )
            return response
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __create_message_identity__(self, provider: Any):
        """
        Create a Slack message identity based on the provider type.

        Parameters:
        - provider (Provider): The Provider (e.g. "AwsProvider", "GcpProvider", "AzureProvide").

        Returns:
        - identity (str): The message identity based on the provider type.
        - logo (str): The logo URL associated with the provider type.
        """

        # TODO: support kubernetes
        try:
            identity = ""
            logo = aws_logo
            if provider.type == "aws":
                identity = f"AWS Account *{provider.identity.account}*"
            elif provider.type == "gcp":
                identity = f"GCP Projects *{', '.join(provider.project_ids)}*"
                logo = gcp_logo
            elif provider.type == "azure":
                printed_subscriptions = []
                for key, value in provider.identity.subscriptions.items():
                    intermediate = f"- *{key}: {value}*\n"
                    printed_subscriptions.append(intermediate)
                identity = f"Azure Subscriptions:\n{''.join(printed_subscriptions)}"
                logo = azure_logo
            return identity, logo
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __create_message_blocks__(self, identity, logo, stats, args) -> list:
        """
        Create the Slack message blocks.

        Args:
            identity: message identity.
            logo: logo URL.
            stats: audit statistics.
            args: command line arguments used.

        Returns:
            list: list of Slack message blocks.
        """
        try:
            blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": self.__create_title__(identity, stats),
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
                        "text": (
                            "*Severities:*\n"
                            f"• *Critical:* {stats['total_critical_severity_pass']} "
                            f"• *High:* {stats['total_high_severity_pass']} "
                            f"• *Medium:* {stats['total_medium_severity_pass']} "
                            f"• *Low:* {stats['total_low_severity_pass']}"
                        ),
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
                        "text": (
                            "*Severities:*\n"
                            f"• *Critical:* {stats['total_critical_severity_fail']} "
                            f"• *High:* {stats['total_high_severity_fail']} "
                            f"• *Medium:* {stats['total_medium_severity_fail']} "
                            f"• *Low:* {stats['total_low_severity_fail']}"
                        ),
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
                            "text": f"Used parameters: `prowler {args}`",
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
                        "url": "https://goto.prowler.com/slack",
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

    def __create_title__(self, identity, stats) -> str:
        """
        Create the Slack message title.

        Args:
            identity: message identity.
            stats: audit statistics.

        Returns:
            str: Slack message title.
        """
        try:
            title = f"Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {identity} with a total of *{stats['findings_count']}* findings."
            return title
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def test_connection(
        token: str,
        channel: str,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test the Slack connection by validating the provided token and channel.

        Args:
            token (str): The Slack token to be tested.
            channel (str): The Slack channel to be validated.

        Returns:
            Connection: A Connection object.
        """
        try:
            client = WebClient(token=token)
            # Test if the token is valid
            auth_response = client.auth_test()
            if auth_response["ok"]:
                # Test if the channel is accessible
                channels_response = client.conversations_info(
                    token=token, channel=channel
                )
                if channels_response["ok"]:
                    return Connection(is_connected=True)
                else:
                    exception = SlackChannelNotFound(
                        file=os.path.basename(__file__),
                        message=(
                            channels_response["error"]
                            if "error" in channels_response
                            else "Unknown error"
                        ),
                    )
                    if raise_on_exception:
                        raise exception
                    return Connection(error=exception)
            else:
                exception = SlackNoCredentialsError(
                    file=os.path.basename(__file__),
                    message=(
                        auth_response["error"]
                        if "error" in auth_response
                        else "Unknown error"
                    ),
                )
                if raise_on_exception:
                    raise exception
                return Connection(error=exception)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise SlackClientError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                ) from error
            return Connection(error=error)
