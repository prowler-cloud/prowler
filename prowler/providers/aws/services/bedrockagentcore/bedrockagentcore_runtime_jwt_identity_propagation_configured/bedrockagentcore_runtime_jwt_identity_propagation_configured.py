from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_jwt_identity_propagation_configured(Check):
    """Ensure Bedrock AgentCore runtimes are configured with a custom JWT authorizer.

    - PASS: The runtime has a custom JWT authorizer configured, enabling
      end-user identity propagation to downstream tools.
    - FAIL: The runtime has no custom JWT authorizer configured and relies solely on
      the agent execution role.
    - MANUAL: Detail retrieval failed for a runtime or runtime listing failed in a region
      (e.g., AccessDenied).
    """

    def execute(self) -> list[Check_Report_AWS]:
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
            report.status_extended = f"Bedrock AgentCore runtimes could not be listed in region {region} ({error}); verify manually that every runtime is configured with a custom JWT authorizer."
            findings.append(report)

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)

            if not runtime.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} authorizer configuration could not be retrieved in region {runtime.region}; verify manually that it is configured with a custom JWT authorizer."
            elif (
                runtime.authorizer_configuration
                and runtime.authorizer_configuration.custom_jwt_authorizer
            ):
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} is configured with a custom JWT authorizer for end-user identity propagation in region {runtime.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} does not have a custom JWT authorizer configured and relies solely on the execution role in region {runtime.region}."

            findings.append(report)

        return findings
