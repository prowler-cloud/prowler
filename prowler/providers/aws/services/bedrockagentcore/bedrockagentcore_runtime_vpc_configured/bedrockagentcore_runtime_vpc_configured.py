from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_vpc_configured(Check):
    """Ensure Bedrock AgentCore runtimes use VPC network mode.

    The API requires subnets and security groups for VPC mode, so the network mode alone
    decides the result.
    - PASS: The runtime uses VPC network mode.
    - FAIL: The runtime uses PUBLIC network mode.
    - MANUAL: Runtimes could not be listed in a region, or the runtime detail could not be retrieved.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
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
            report.status_extended = f"Bedrock AgentCore runtimes could not be listed in region {region} ({error}); verify manually that every runtime uses VPC network mode."
            findings.append(report)

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
            if not runtime.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} network configuration could not be retrieved in region {runtime.region}; verify manually that it uses VPC network mode."
            elif runtime.network_mode == "VPC":
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} uses VPC network mode in region {runtime.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} uses {runtime.network_mode or 'PUBLIC'} network mode instead of VPC in region {runtime.region}."
            findings.append(report)

        return findings
