from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client

# Official AgentCore PrivateLink service suffixes, longest first so
# bedrock-agentcore.gateway is not counted as the data-plane service.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
AGENTCORE_ENDPOINT_SERVICES = {
    "bedrock-agentcore.gateway": "AgentCore gateway",
    "bedrock-agentcore-control": "AgentCore control plane",
    "bedrock-agentcore": "AgentCore data plane",
}


def _matched_endpoint_service(service_name: str) -> str | None:
    """Return the AgentCore service suffix matched by a VPC endpoint service name."""
    for suffix in AGENTCORE_ENDPOINT_SERVICES:
        if service_name.endswith(f".{suffix}"):
            return suffix
    return None


class bedrockagentcore_vpc_endpoints_configured(Check):
    """Ensure VPCs that host AgentCore runtimes have AgentCore interface endpoints.

    Evaluates each VPC that contains at least one AgentCore runtime in VPC
    network mode against the three AgentCore PrivateLink services (data plane,
    control plane, and gateway). Only endpoints in the ``available`` state count.
    - PASS: the VPC has an available interface endpoint for every AgentCore service.
    - FAIL: one or more required endpoints are missing or not available.
    - MANUAL: runtime inventory or VPC placement could not be determined.
    Public-mode runtimes do not produce findings, because they are not in a customer VPC.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        scan_error_regions = set(
            (bedrockagentcore_client.agent_runtimes_scan_errors or {}).keys()
        )
        for region, error in (
            bedrockagentcore_client.agent_runtimes_scan_errors or {}
        ).items():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "runtime/unknown"
            report.resource_arn = (
                f"arn:{bedrockagentcore_client.audited_partition}:"
                f"bedrock-agentcore:{region}:"
                f"{bedrockagentcore_client.audited_account}:runtime/unknown"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Could not list AgentCore runtimes in region {region} "
                f"({error}); runtime VPC endpoint coverage is indeterminate."
            )
            findings.append(report)

        vpc_ids_to_evaluate: set[str] = set()
        for runtime in bedrockagentcore_client.agent_runtimes.values():
            if runtime.region in scan_error_regions:
                # Regional MANUAL already covers incomplete inventory; do not
                # emit PASS/FAIL from a partial page of runtimes.
                continue

            if not runtime.detail_retrieved or runtime.network_mode is None:
                report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
                report.status = "MANUAL"
                if not runtime.detail_retrieved:
                    report.status_extended = (
                        f"Bedrock AgentCore runtime {runtime.name} in region "
                        f"{runtime.region} could not be described; its VPC "
                        "placement and endpoint coverage are indeterminate."
                    )
                else:
                    report.status_extended = (
                        f"Bedrock AgentCore runtime {runtime.name} in region "
                        f"{runtime.region} has no network mode; its VPC "
                        "placement and endpoint coverage are indeterminate."
                    )
                findings.append(report)
                continue

            if runtime.network_mode != "VPC":
                continue

            vpc_ids = self._vpc_ids_for_runtime(runtime)
            if vpc_ids is None:
                report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock AgentCore runtime {runtime.name} uses VPC network "
                    f"mode in region {runtime.region}, but its subnets could not "
                    "be resolved to a VPC; endpoint coverage is indeterminate."
                )
                findings.append(report)
                continue

            vpc_ids_to_evaluate.update(vpc_ids)

        for vpc_id in vpc_ids_to_evaluate:
            vpc = vpc_client.vpcs.get(vpc_id)
            if not vpc:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
            found_services = set()
            for endpoint in vpc_client.vpc_endpoints:
                if (
                    endpoint.vpc_id != vpc_id
                    or endpoint.state != "available"
                    or endpoint.type != "Interface"
                ):
                    continue
                matched = _matched_endpoint_service(endpoint.service_name)
                if matched:
                    found_services.add(matched)

            missing_services = [
                suffix
                for suffix in AGENTCORE_ENDPOINT_SERVICES
                if suffix not in found_services
            ]
            if not missing_services:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC {vpc.id} has available VPC endpoints for all "
                    "AgentCore services."
                )
            else:
                missing_labels = [
                    AGENTCORE_ENDPOINT_SERVICES[suffix] for suffix in missing_services
                ]
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.id} does not have available VPC endpoints for the "
                    f"following AgentCore services: {', '.join(missing_labels)}."
                )
            findings.append(report)

        return findings

    @staticmethod
    def _vpc_ids_for_runtime(runtime) -> set[str] | None:
        """Map a VPC-mode runtime's subnets to VPC IDs.

        Returns None when placement cannot be determined.
        """
        if not runtime.subnets:
            return None

        vpc_ids: set[str] = set()
        for subnet_id in runtime.subnets:
            subnet = vpc_client.vpc_subnets.get(subnet_id)
            if not subnet or subnet.vpc_id not in vpc_client.vpcs:
                return None
            vpc_ids.add(subnet.vpc_id)
        return vpc_ids or None
