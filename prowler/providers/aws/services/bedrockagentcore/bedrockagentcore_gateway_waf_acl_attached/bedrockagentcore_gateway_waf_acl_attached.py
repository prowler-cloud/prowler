from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_gateway_waf_acl_attached(Check):
    """Ensure each Bedrock AgentCore gateway has an AWS WAF web ACL associated.

    WAF GetWebACLForResource returns the regional web ACL associated with the gateway.
    - PASS: The gateway has a web ACL.
    - FAIL: The lookup succeeded and returned no web ACL.
    - MANUAL: The gateway inventory or the WAF lookup could not be completed.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(
            (bedrockagentcore_client.gateways_scan_errors or {}).items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "gateway/unknown"
            report.resource_arn = (
                f"arn:{bedrockagentcore_client.audited_partition}:"
                f"bedrock-agentcore:{region}:"
                f"{bedrockagentcore_client.audited_account}:gateway/unknown"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Could not list AgentCore gateways in region {region} "
                f"({error}); WAF coverage is indeterminate."
            )
            findings.append(report)

        for gateway in bedrockagentcore_client.gateways.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=gateway)
            if not gateway.web_acl_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock AgentCore gateway {gateway.name} in region "
                    f"{gateway.region} could not have its WAF association "
                    "retrieved; coverage is indeterminate."
                )
            elif gateway.web_acl_arn:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock AgentCore gateway {gateway.name} is associated "
                    f"with an AWS WAF web ACL in region {gateway.region}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock AgentCore gateway {gateway.name} is not associated "
                    f"with an AWS WAF web ACL in region {gateway.region}."
                )
            findings.append(report)

        return findings
