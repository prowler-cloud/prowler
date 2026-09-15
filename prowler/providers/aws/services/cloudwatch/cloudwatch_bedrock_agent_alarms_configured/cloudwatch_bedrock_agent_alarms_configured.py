from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)

AGENT_METRICS = {
    ("AWS/Bedrock/Agents", "InvocationCount"),
    ("AWS/Bedrock/Agents", "InvocationThrottles"),
}
AGENT_OPERATIONS = {"InvokeAgent", "InvokeInlineAgent"}
AGENT_DIMENSIONS = {
    frozenset({"Operation"}),
    frozenset({"Operation", "AgentAliasArn", "ModelId"}),
}


class cloudwatch_bedrock_agent_alarms_configured(Check):
    """Check Bedrock Agent rate alarm coverage by region."""

    def execute(self) -> list[Check_Report_AWS]:
        """Return regional findings for agents and inventory errors."""
        findings = []
        agent_regions = {agent.region for agent in bedrock_agent_client.agents.values()}
        agent_regions.update(bedrock_agent_client.agents_scan_errors)
        covered_regions = {
            alarm.region
            for alarm in cloudwatch_client.all_metric_alarms or []
            if alarm.actions_enabled
            and any(self._covers_agent_metric(ref) for ref in alarm.metric_references)
        }

        for region in sorted(agent_regions):
            report = self._report_for_region(region)
            bedrock_error = bedrock_agent_client.agents_scan_errors.get(region)
            cloudwatch_error = cloudwatch_client.metric_alarms_scan_errors.get(region)
            if bedrock_error:
                report.status = "MANUAL"
                report.status_extended = (
                    "Cannot evaluate Bedrock Agent alarm coverage in region "
                    f"{region}: bedrock:ListAgents returned {bedrock_error}. "
                    "Check API access and retry the scan."
                )
            elif cloudwatch_error:
                report.status = "MANUAL"
                report.status_extended = (
                    "Cannot evaluate Bedrock Agent alarm coverage in region "
                    f"{region}: cloudwatch:DescribeAlarms returned "
                    f"{cloudwatch_error}. Check API access and retry the scan."
                )
            elif region not in cloudwatch_client.metric_alarms_scanned_regions:
                report.status = "MANUAL"
                report.status_extended = (
                    "Cannot evaluate Bedrock Agent alarm coverage in region "
                    f"{region}: CloudWatch alarms were not scanned."
                )
            elif region in covered_regions:
                report.status = "PASS"
                report.status_extended = (
                    "CloudWatch has an enabled alarm for Bedrock Agent invocation "
                    f"or throttling metrics in region {region}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "CloudWatch has no enabled alarms for Bedrock Agent invocation "
                    f"or throttling metrics in region {region}."
                )
            findings.append(report)

        return findings

    @staticmethod
    def _covers_agent_metric(reference) -> bool:
        """Return whether a metric reference covers an Agent rate signal.

        Args:
            reference: Metric reference collected from an alarm.

        Returns:
            True for an in-account Agent invocation or throttling metric.
        """
        if (reference.namespace, reference.name) not in AGENT_METRICS:
            return False
        if (
            reference.account_id is not None
            and reference.account_id != cloudwatch_client.audited_account
        ):
            return False
        if frozenset(reference.dimensions) not in AGENT_DIMENSIONS:
            return False
        return reference.dimensions.get("Operation") in AGENT_OPERATIONS and all(
            reference.dimensions.values()
        )

    def _report_for_region(self, region: str) -> Check_Report_AWS:
        """Create the report identity for an AWS region.

        Args:
            region: AWS region being evaluated.

        Returns:
            Report populated with the check's regional resource identity.
        """
        report = Check_Report_AWS(metadata=self.metadata(), resource={})
        report.region = region
        report.resource_id = "bedrock-agent-alarms"
        report.resource_arn = (
            f"arn:{cloudwatch_client.audited_partition}:cloudwatch:{region}:"
            f"{cloudwatch_client.audited_account}:alarm"
        )
        return report
