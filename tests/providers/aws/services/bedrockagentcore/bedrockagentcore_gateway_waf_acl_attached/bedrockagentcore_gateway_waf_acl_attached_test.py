from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreGateway,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

GATEWAY_ID = "gw-12345"
GATEWAY_NAME = "test-gateway"
GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{GATEWAY_ID}"
WEB_ACL_ARN = (
    f"arn:aws:wafv2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    ":regional/webacl/gateway-acl/a1b2c3d4-5678-90ab-cdef-example11111"
)
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_gateway_waf_acl_attached.bedrockagentcore_gateway_waf_acl_attached"


def _gateway(web_acl_arn=None, web_acl_retrieved=True):
    return AgentCoreGateway(
        id=GATEWAY_ID,
        name=GATEWAY_NAME,
        arn=GATEWAY_ARN,
        region=AWS_REGION_US_EAST_1,
        web_acl_arn=web_acl_arn,
        web_acl_retrieved=web_acl_retrieved,
    )


def _run(gateways=(), scan_errors=None):
    client = mock.MagicMock()
    client.gateways = {gateway.arn: gateway for gateway in gateways}
    client.gateways_scan_errors = scan_errors or {}
    client.audited_partition = "aws"
    client.audited_account = AWS_ACCOUNT_NUMBER
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_gateway_waf_acl_attached.bedrockagentcore_gateway_waf_acl_attached import (
            bedrockagentcore_gateway_waf_acl_attached,
        )

        return bedrockagentcore_gateway_waf_acl_attached().execute()


class Test_bedrockagentcore_gateway_waf_acl_attached:
    def test_no_gateways(self):
        assert _run() == []

    def test_gateway_with_web_acl_passes(self):
        result = _run([_gateway(WEB_ACL_ARN)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore gateway {GATEWAY_NAME} is associated with an AWS WAF web ACL in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == GATEWAY_ID
        assert result[0].resource_arn == GATEWAY_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_gateway_without_web_acl_fails(self):
        result = _run([_gateway()])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore gateway {GATEWAY_NAME} is not associated with an AWS WAF web ACL in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == GATEWAY_ID
        assert result[0].resource_arn == GATEWAY_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_failed_web_acl_lookup_has_no_finding(self):
        assert _run([_gateway(web_acl_retrieved=False)]) == []

    def test_unlisted_region_has_no_finding(self):
        result = _run(
            [_gateway(WEB_ACL_ARN)],
            scan_errors={AWS_REGION_EU_WEST_1: "AccessDeniedException"},
        )
        assert [finding.status for finding in result] == ["PASS"]
        assert result[0].region == AWS_REGION_US_EAST_1
