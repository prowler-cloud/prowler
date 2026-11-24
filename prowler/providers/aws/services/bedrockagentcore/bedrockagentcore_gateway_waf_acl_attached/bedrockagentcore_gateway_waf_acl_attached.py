from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_gateway_waf_acl_attached(Check):
    """Ensure each Bedrock AgentCore gateway has an AWS WAF web ACL associated.

    WAF GetWebACLForResource returns the regional web ACL associated with the gateway.
    - PASS: The gateway has a web ACL.
    - FAIL: The lookup succeeded and returned no web ACL.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for gateway in bedrockagentcore_client.gateways.values():
            if not gateway.web_acl_retrieved:
                continue  # unreadable: no finding, the service already logged the error
            report = Check_Report_AWS(metadata=self.metadata(), resource=gateway)
            if gateway.web_acl_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} is associated with an AWS WAF web ACL in region {gateway.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} is not associated with an AWS WAF web ACL in region {gateway.region}."
            findings.append(report)

        return findings
