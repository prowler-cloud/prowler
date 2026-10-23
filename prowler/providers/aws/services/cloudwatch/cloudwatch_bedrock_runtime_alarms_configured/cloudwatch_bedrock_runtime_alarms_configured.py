from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)

BEDROCK_RUNTIME_NAMESPACE = "AWS/Bedrock"


class cloudwatch_bedrock_runtime_alarms_configured(Check):
    """Ensure CloudWatch alarms cover Amazon Bedrock runtime metrics.

    Evaluated as one regional posture result per region that has Bedrock
    resources (guardrails, custom models, agents, knowledge bases, prompts, or
    model invocation logging), since AWS/Bedrock runtime metrics are only
    meaningful where Bedrock is actually in use:
    - PASS: at least one enabled alarm references the AWS/Bedrock namespace,
      directly or through a metric-math expression.
    - FAIL: the region has Bedrock resources but no such alarm exists.
    - MANUAL: CloudWatch alarms could not be listed, so coverage is unknown.
    - No finding: the region has no Bedrock resources.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        regions_with_bedrock_resources = self._regions_with_bedrock_resources()
        if not regions_with_bedrock_resources:
            return findings

        if cloudwatch_client.metric_alarms is None:
            for region in sorted(regions_with_bedrock_resources):
                report = self._report_for_region(region)
                report.status = "MANUAL"
                report.status_extended = (
                    f"CloudWatch alarms could not be listed in region {region}; "
                    "verify manually that an enabled alarm covers Amazon Bedrock "
                    f"runtime metrics ({BEDROCK_RUNTIME_NAMESPACE})."
                )
                findings.append(report)
            return findings

        covered_regions = {
            alarm.region
            for alarm in cloudwatch_client.metric_alarms
            if alarm.actions_enabled and BEDROCK_RUNTIME_NAMESPACE in alarm.namespaces
        }

        for region in sorted(regions_with_bedrock_resources):
            report = self._report_for_region(region)
            if region in covered_regions:
                report.status = "PASS"
                report.status_extended = (
                    "At least one enabled CloudWatch alarm covers Amazon Bedrock "
                    f"runtime metrics ({BEDROCK_RUNTIME_NAMESPACE}) in region {region}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "No enabled CloudWatch alarm covers Amazon Bedrock runtime "
                    f"metrics ({BEDROCK_RUNTIME_NAMESPACE}) in region {region}."
                )
            findings.append(report)

        return findings

    def _report_for_region(self, region: str) -> Check_Report_AWS:
        report = Check_Report_AWS(metadata=self.metadata(), resource={})
        report.region = region
        report.resource_id = "bedrock-runtime-alarms"
        report.resource_arn = (
            f"arn:{cloudwatch_client.audited_partition}:cloudwatch:{region}:"
            f"{cloudwatch_client.audited_account}:alarm"
        )
        return report

    @staticmethod
    def _regions_with_bedrock_resources() -> set[str]:
        """Regions where Bedrock is actually in use.

        AWS/Bedrock runtime metrics have no independent inventory of their own
        (they are emitted on invocation, not on a listable resource), so
        presence of any existing Bedrock resource is used as the signal that
        the region is in scope for this check.
        """
        regions = set()
        for guardrail in bedrock_client.guardrails.values():
            regions.add(guardrail.region)
        for model in bedrock_client.custom_models.values():
            regions.add(model.region)
        for region, logging_configuration in (
            bedrock_client.logging_configurations or {}
        ).items():
            if logging_configuration.enabled:
                regions.add(region)
        for agent in bedrock_agent_client.agents.values():
            regions.add(agent.region)
        for knowledge_base in bedrock_agent_client.knowledge_bases.values():
            regions.add(knowledge_base.region)
        for prompt in bedrock_agent_client.prompts.values():
            regions.add(prompt.region)
        return regions
