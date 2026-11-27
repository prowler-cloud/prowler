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
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
            if runtime.network_mode == "VPC":
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} uses VPC network mode in region {runtime.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore runtime {runtime.name} uses {runtime.network_mode or 'PUBLIC'} network mode instead of VPC in region {runtime.region}."
            findings.append(report)

        return findings
