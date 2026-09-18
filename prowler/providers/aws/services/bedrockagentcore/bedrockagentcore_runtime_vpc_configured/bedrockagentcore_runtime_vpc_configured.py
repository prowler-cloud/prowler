from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentRuntime,
)


class bedrockagentcore_runtime_vpc_configured(Check):
    """Ensure Bedrock AgentCore runtimes use VPC network mode.

    This check evaluates each Amazon Bedrock AgentCore runtime for VPC
    networking with required subnets and security groups.
    - PASS: networkMode is VPC and networkModeConfig has subnets and security groups.
    - FAIL: networkMode is PUBLIC/default, or VPC mode is missing required fields.
    - MANUAL: runtime listing failed in a region or runtime detail could not be retrieved.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the PASS, FAIL, or MANUAL results.
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
            report.resource_arn = (
                f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:"
                f"{region}:{bedrockagentcore_client.audited_account}:runtime/unknown"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Bedrock AgentCore runtimes could not be listed in region {region} "
                f"({error}); verify manually that every runtime uses VPC network mode "
                f"with subnets and security groups."
            )
            findings.append(report)

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)

            if not runtime.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock AgentCore runtime {runtime.name} network configuration "
                    f"could not be retrieved in region {runtime.region}; verify "
                    f"manually that it uses VPC network mode with subnets and "
                    f"security groups."
                )
            elif _is_vpc_configured(runtime):
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock AgentCore runtime {runtime.name} is configured with VPC "
                    f"network mode and has subnets and security groups in region "
                    f"{runtime.region}."
                )
            elif runtime.network_mode == "VPC":
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock AgentCore runtime {runtime.name} uses VPC network mode "
                    f"but is missing required subnets or security groups in region "
                    f"{runtime.region}."
                )
            else:
                network_mode = runtime.network_mode or "PUBLIC"
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock AgentCore runtime {runtime.name} is configured with "
                    f"{network_mode} network mode instead of VPC in region "
                    f"{runtime.region}."
                )

            findings.append(report)

        return findings


def _is_vpc_configured(runtime: AgentRuntime) -> bool:
    """Return whether a runtime has VPC mode with subnets and security groups.

    Args:
        runtime: AgentRuntime collected by the AgentCore service.

    Returns:
        True when networkMode is VPC and both subnets and security groups are set.
    """
    if runtime.network_mode != "VPC" or not runtime.network_mode_config:
        return False
    return bool(runtime.network_mode_config.subnets) and bool(
        runtime.network_mode_config.security_groups
    )
