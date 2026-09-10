from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_jwt_identity_propagation_configured(Check):
    """Ensure Bedrock AgentCore runtimes are configured with custom JWT authorization and identity propagation.

    - PASS: The runtime has a custom JWT authorizer configured and allows the Authorization header
      in requestHeaderAllowlist (case-insensitive) to propagate end-user identity tokens to downstream tools.
    - FAIL: The runtime has no custom JWT authorizer configured or does not include Authorization in its
      requestHeaderAllowlist, relying solely on the agent execution role.
    - MANUAL: Detail retrieval failed for a runtime or runtime listing failed in a region (e.g., AccessDenied).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            list[Check_Report_AWS]: A list of reports containing the PASS, FAIL, or MANUAL results.
        """
        findings = []

        for region, error in sorted(
            bedrockagentcore_client.agent_runtimes_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "runtime/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:runtime/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore runtimes could not be listed in region {region} ({error}); verify manually that every runtime is configured with a custom JWT authorizer and downstream identity propagation."
            findings.append(report)

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)

            if not runtime.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} configuration could not be retrieved in region {runtime.region}; verify manually that it is configured with a custom JWT authorizer and downstream identity propagation."
            else:
                has_jwt = bool(
                    runtime.authorizer_configuration
                    and runtime.authorizer_configuration.custom_jwt_authorizer
                )
                headers = (
                    runtime.request_header_configuration.request_header_allowlist
                    if runtime.request_header_configuration
                    and runtime.request_header_configuration.request_header_allowlist
                    else []
                )
                has_auth_header = any(h.lower() == "authorization" for h in headers)

                if has_jwt and has_auth_header:
                    report.status = "PASS"
                    report.status_extended = f"Bedrock AgentCore runtime {runtime.name} is configured with a custom JWT authorizer and downstream identity propagation in region {runtime.region}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Bedrock AgentCore runtime {runtime.name} does not have a custom JWT authorizer and downstream identity propagation configured and relies solely on the execution role in region {runtime.region}."

            findings.append(report)

        return findings
