from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreCodeInterpreter,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

INTERPRETER_ID = "interpreter-12345"
INTERPRETER_NAME = "test-interpreter"
INTERPRETER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:code-interpreter/{INTERPRETER_ID}"
SYSTEM_INTERPRETER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:aws:code-interpreter/aws.codeinterpreter.v1"
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_code_interpreter_vpc_configured.bedrockagentcore_code_interpreter_vpc_configured"


def _interpreter(
    network_mode="VPC",
    detail_retrieved=True,
    arn=INTERPRETER_ARN,
    name=INTERPRETER_NAME,
):
    return AgentCoreCodeInterpreter(
        id=INTERPRETER_ID,
        name=name,
        arn=arn,
        region=AWS_REGION_US_EAST_1,
        network_mode=network_mode,
        detail_retrieved=detail_retrieved,
    )


def _run(interpreters=()):
    client = mock.MagicMock()
    client.code_interpreters = {
        interpreter.arn: interpreter for interpreter in interpreters
    }
    client.audited_account = AWS_ACCOUNT_NUMBER
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_code_interpreter_vpc_configured.bedrockagentcore_code_interpreter_vpc_configured import (
            bedrockagentcore_code_interpreter_vpc_configured,
        )

        return bedrockagentcore_code_interpreter_vpc_configured().execute()


class Test_bedrockagentcore_code_interpreter_vpc_configured:
    def test_no_code_interpreters(self):
        assert _run() == []

    def test_vpc_code_interpreter_passes(self):
        result = _run([_interpreter("VPC")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore code interpreter {INTERPRETER_NAME} uses VPC network mode in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == INTERPRETER_ID
        assert result[0].resource_arn == INTERPRETER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_sandbox_code_interpreter_passes(self):
        result = _run([_interpreter("SANDBOX")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore code interpreter {INTERPRETER_NAME} uses SANDBOX network mode in region {AWS_REGION_US_EAST_1}."
        )

    def test_public_code_interpreter_fails(self):
        result = _run([_interpreter("PUBLIC")])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore code interpreter {INTERPRETER_NAME} uses PUBLIC network mode instead of VPC or SANDBOX in region {AWS_REGION_US_EAST_1}."
        )

    def test_missing_network_mode_is_reported_as_public(self):
        result = _run([_interpreter(None)])
        assert result[0].status == "FAIL"
        assert "uses PUBLIC network mode" in result[0].status_extended

    def test_unretrieved_detail_has_no_finding(self):
        assert _run([_interpreter(None, detail_retrieved=False)]) == []

    def test_aws_owned_system_interpreter_has_no_finding(self):
        assert (
            _run(
                [
                    _interpreter(
                        "SANDBOX",
                        arn=SYSTEM_INTERPRETER_ARN,
                        name="aws.codeinterpreter.v1",
                    )
                ]
            )
            == []
        )

    def test_multiple_code_interpreters(self):
        result = _run(
            [
                _interpreter("VPC"),
                _interpreter(
                    "PUBLIC",
                    arn=f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:code-interpreter/interpreter-67890",
                    name="other-interpreter",
                ),
            ]
        )
        assert [finding.status for finding in result] == ["PASS", "FAIL"]
