from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_browser_vpc_configured(Check):
    """Ensure Bedrock AgentCore browsers use VPC network mode.

    A browser drives web sessions for the agent. PUBLIC mode gives it direct
    internet access, while VPC mode confines it to customer subnets behind
    customer security groups.
    - PASS: The browser uses VPC network mode.
    - FAIL: The browser uses PUBLIC network mode.
    - No finding: The AWS-owned built-in browser (aws.browser.v1), which runs in
      PUBLIC mode only and cannot be reconfigured, or a resource whose detail
      could not be read.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for browser in bedrockagentcore_client.browsers.values():
            if not browser.detail_retrieved:
                continue  # unreadable: no finding, the service already logged the error
            if browser.arn.split(":")[4] != bedrockagentcore_client.audited_account:
                continue  # AWS-owned built-in: not configurable, never flag it
            report = Check_Report_AWS(metadata=self.metadata(), resource=browser)
            if browser.network_mode == "VPC":
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} uses VPC network mode in region {browser.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} uses {browser.network_mode or 'PUBLIC'} network mode instead of VPC in region {browser.region}."
            findings.append(report)

        return findings
