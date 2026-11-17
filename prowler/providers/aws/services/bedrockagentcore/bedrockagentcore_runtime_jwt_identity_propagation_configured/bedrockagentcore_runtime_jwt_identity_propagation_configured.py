from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_jwt_identity_propagation_configured(Check):
    """Ensure Bedrock AgentCore runtimes forward the end-user JWT to the agent.

    - PASS: The runtime has a custom JWT authorizer and allows the Authorization header
      in its request header allowlist, so the end-user token reaches the agent code.
    - FAIL: The runtime has a custom JWT authorizer but drops the Authorization header,
      so the agent can only act under its execution role.
    - No finding: The runtime uses IAM (SigV4) inbound auth, whose callers are IAM
      principals rather than end users, or its configuration could not be retrieved.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            if not runtime.detail_retrieved:
                continue  # unreadable: no finding, the service already logged the error
            if not (runtime.authorizer_configuration or {}).get("customJWTAuthorizer"):
                continue  # IAM (SigV4) auth: no end-user token to propagate

            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
            if any(
                header.lower() == "authorization"
                for header in runtime.request_header_allowlist
            ):
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} validates end-user JWTs and forwards the Authorization header to the agent in region {runtime.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} validates end-user JWTs but does not forward the Authorization header to the agent in region {runtime.region}."
            findings.append(report)

        return findings
