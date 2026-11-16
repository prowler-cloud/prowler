from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreRuntime,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

RUNTIME_ID = "runtime-12345"
RUNTIME_NAME = "test-runtime"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/{RUNTIME_ID}"
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_vpc_configured.bedrockagentcore_runtime_vpc_configured"


def _runtime(network_mode="VPC", detail_retrieved=True):
    return AgentCoreRuntime(
        id=RUNTIME_ID,
        name=RUNTIME_NAME,
        arn=RUNTIME_ARN,
        region=AWS_REGION_US_EAST_1,
        network_mode=network_mode,
        detail_retrieved=detail_retrieved,
    )


def _run(runtimes=(), scan_errors=None):
    client = mock.MagicMock()
    client.agent_runtimes = {runtime.arn: runtime for runtime in runtimes}
    client.agent_runtimes_scan_errors = scan_errors or {}
    client.audited_partition = "aws"
    client.audited_account = AWS_ACCOUNT_NUMBER
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_vpc_configured.bedrockagentcore_runtime_vpc_configured import (
            bedrockagentcore_runtime_vpc_configured,
        )

        return bedrockagentcore_runtime_vpc_configured().execute()


class Test_bedrockagentcore_runtime_vpc_configured:
    def test_no_runtimes(self):
        assert _run() == []

    def test_vpc_runtime_passes(self):
        result = _run([_runtime("VPC")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} uses VPC network mode in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_public_runtime_fails(self):
        result = _run([_runtime("PUBLIC")])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} uses PUBLIC network mode instead of VPC in region {AWS_REGION_US_EAST_1}."
        )

    def test_missing_network_mode_is_reported_as_public(self):
        result = _run([_runtime(None)])
        assert result[0].status == "FAIL"
        assert "uses PUBLIC network mode" in result[0].status_extended

    def test_unretrieved_detail_is_manual(self):
        result = _run([_runtime(None, detail_retrieved=False)])
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    def test_unlisted_region_is_manual(self):
        result = _run(
            [_runtime("VPC")],
            scan_errors={AWS_REGION_EU_WEST_1: "AccessDeniedException"},
        )
        assert [finding.status for finding in result] == ["MANUAL", "PASS"]
        assert result[0].region == AWS_REGION_EU_WEST_1
        assert result[0].resource_id == "runtime/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:runtime/unknown"
        )
        assert "AccessDeniedException" in result[0].status_extended
