from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client

BEDROCK_ENDPOINT_SERVICES = {
    "bedrock": "Bedrock control plane",
    "bedrock-runtime": "Bedrock runtime",
    "bedrock-agent": "Bedrock agent control plane",
    "bedrock-agent-runtime": "Bedrock agent runtime",
    "bedrock-mantle": "Bedrock Mantle (OpenAI-compatible API)",
}


class bedrock_vpc_endpoints_configured(Check):
    """Ensure VPC endpoints are configured for Bedrock services.

    This check verifies that each VPC in regions with Bedrock activity has
    interface VPC endpoints for all Amazon Bedrock services (control plane,
    runtime, agent, agent runtime, and Mantle OpenAI-compatible API),
    ensuring that traffic to these services remains within the AWS network.
    - PASS: The VPC has VPC endpoints for all Bedrock services.
    - FAIL: The VPC is missing one or more Bedrock VPC endpoints.
    VPCs in regions without Bedrock activity are skipped.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        bedrock_regions = self._get_bedrock_active_regions()

        for vpc_id, vpc in vpc_client.vpcs.items():
            if not (vpc_client.provider.scan_unused_services or vpc.in_use):
                continue

            if vpc.region not in bedrock_regions:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
            report.status = "FAIL"

            found_services = set()

            for endpoint in vpc_client.vpc_endpoints:
                if endpoint.vpc_id == vpc_id and endpoint.state == "available":
                    for svc_suffix in BEDROCK_ENDPOINT_SERVICES:
                        if endpoint.service_name.endswith(f".{svc_suffix}"):
                            found_services.add(svc_suffix)

            missing_services = set(BEDROCK_ENDPOINT_SERVICES) - found_services

            if not missing_services:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC {vpc.id} has VPC endpoints for all Bedrock services."
                )
            else:
                missing_labels = [
                    BEDROCK_ENDPOINT_SERVICES[svc] for svc in sorted(missing_services)
                ]
                report.status_extended = f"VPC {vpc.id} does not have VPC endpoints for the following Bedrock services: {', '.join(missing_labels)}."

            findings.append(report)

        return findings

    @staticmethod
    def _get_bedrock_active_regions() -> set[str]:
        """Return regions where Bedrock resources or logging are configured."""
        active_regions = set()

        for region, config in bedrock_client.logging_configurations.items():
            if config.enabled:
                active_regions.add(region)

        for guardrail in bedrock_client.guardrails.values():
            active_regions.add(guardrail.region)

        for agent in bedrock_agent_client.agents.values():
            active_regions.add(agent.region)

        return active_regions
