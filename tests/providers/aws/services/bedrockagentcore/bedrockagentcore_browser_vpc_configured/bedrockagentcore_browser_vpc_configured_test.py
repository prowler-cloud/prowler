from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreBrowser,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

BROWSER_ID = "browser-12345"
BROWSER_NAME = "test-browser"
BROWSER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/{BROWSER_ID}"
SYSTEM_BROWSER_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:aws:browser/aws.browser.v1"
)
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_browser_vpc_configured.bedrockagentcore_browser_vpc_configured"


def _browser(
    network_mode="VPC", detail_retrieved=True, arn=BROWSER_ARN, name=BROWSER_NAME
):
    return AgentCoreBrowser(
        id=BROWSER_ID,
        name=name,
        arn=arn,
        region=AWS_REGION_US_EAST_1,
        network_mode=network_mode,
        detail_retrieved=detail_retrieved,
    )


def _run(browsers=()):
    client = mock.MagicMock()
    client.browsers = {browser.arn: browser for browser in browsers}
    client.audited_account = AWS_ACCOUNT_NUMBER
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_browser_vpc_configured.bedrockagentcore_browser_vpc_configured import (
            bedrockagentcore_browser_vpc_configured,
        )

        return bedrockagentcore_browser_vpc_configured().execute()


class Test_bedrockagentcore_browser_vpc_configured:
    def test_no_browsers(self):
        assert _run() == []

    def test_vpc_browser_passes(self):
        result = _run([_browser("VPC")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore browser {BROWSER_NAME} uses VPC network mode in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == BROWSER_ID
        assert result[0].resource_arn == BROWSER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_public_browser_fails(self):
        result = _run([_browser("PUBLIC")])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore browser {BROWSER_NAME} uses PUBLIC network mode instead of VPC in region {AWS_REGION_US_EAST_1}."
        )

    def test_missing_network_mode_is_reported_as_public(self):
        result = _run([_browser(None)])
        assert result[0].status == "FAIL"
        assert "uses PUBLIC network mode" in result[0].status_extended

    def test_unretrieved_detail_has_no_finding(self):
        assert _run([_browser(None, detail_retrieved=False)]) == []

    def test_aws_owned_system_browser_has_no_finding(self):
        # The AWS-managed browser runs in PUBLIC mode only and cannot be
        # reconfigured, so it must never produce a finding.
        assert (
            _run(
                [
                    _browser(
                        "PUBLIC",
                        arn=SYSTEM_BROWSER_ARN,
                        name="aws.browser.v1",
                    )
                ]
            )
            == []
        )

    def test_multiple_browsers(self):
        result = _run(
            [
                _browser("VPC"),
                _browser(
                    "PUBLIC",
                    arn=f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:browser/browser-67890",
                    name="other-browser",
                ),
            ]
        )
        assert [finding.status for finding in result] == ["PASS", "FAIL"]
