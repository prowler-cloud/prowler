from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreRuntime,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

RUNTIME_ID = "runtime-12345"
RUNTIME_NAME = "test-runtime"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/{RUNTIME_ID}"
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_jwt_identity_propagation_configured.bedrockagentcore_runtime_jwt_identity_propagation_configured"
JWT_AUTHORIZER = {
    "customJWTAuthorizer": {
        "discoveryUrl": "https://idp.example.com/.well-known/openid-configuration",
        "allowedClients": ["client-1"],
    }
}


def _runtime(authorizer_configuration=None, allowlist=(), detail_retrieved=True):
    return AgentCoreRuntime(
        id=RUNTIME_ID,
        name=RUNTIME_NAME,
        arn=RUNTIME_ARN,
        region=AWS_REGION_US_EAST_1,
        authorizer_configuration=authorizer_configuration,
        request_header_allowlist=list(allowlist),
        detail_retrieved=detail_retrieved,
    )


def _run(runtimes=(), scan_errors=None):
    client = mock.MagicMock()
    client.agent_runtimes = {runtime.arn: runtime for runtime in runtimes}
    client.agent_runtimes_scan_errors = scan_errors or {}
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_jwt_identity_propagation_configured.bedrockagentcore_runtime_jwt_identity_propagation_configured import (
            bedrockagentcore_runtime_jwt_identity_propagation_configured,
        )

        return bedrockagentcore_runtime_jwt_identity_propagation_configured().execute()


class Test_bedrockagentcore_runtime_jwt_identity_propagation_configured:
    def test_no_runtimes(self):
        assert _run() == []

    def test_jwt_runtime_forwarding_authorization_passes(self):
        result = _run([_runtime(JWT_AUTHORIZER, ["Authorization"])])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} validates end-user JWTs and forwards the Authorization header to the agent in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_authorization_header_match_is_case_insensitive(self):
        result = _run([_runtime(JWT_AUTHORIZER, ["authorization"])])
        assert result[0].status == "PASS"

    def test_jwt_runtime_without_authorization_header_fails(self):
        result = _run(
            [_runtime(JWT_AUTHORIZER, ["X-Amzn-Bedrock-AgentCore-Runtime-Custom-Foo"])]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} validates end-user JWTs but does not forward the Authorization header to the agent in region {AWS_REGION_US_EAST_1}."
        )

    def test_jwt_runtime_without_header_configuration_fails(self):
        result = _run([_runtime(JWT_AUTHORIZER)])
        assert result[0].status == "FAIL"

    def test_iam_runtime_has_no_finding(self):
        # SigV4 callers are IAM principals, not end users: out of scope.
        assert _run([_runtime(None, ["Authorization"])]) == []

    def test_unretrieved_detail_has_no_finding(self):
        assert _run([_runtime(JWT_AUTHORIZER, detail_retrieved=False)]) == []

    def test_listing_error_has_no_finding(self):
        assert _run(scan_errors={AWS_REGION_US_EAST_1: "AccessDeniedException"}) == []
