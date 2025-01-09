from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.schema_client import schema_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class eventbridge_schema_registry_cross_account_access(Check):
    def execute(self):
        findings = []
        for registry in schema_client.registries.values():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = registry.name
            report.resource_arn = registry.arn
            report.resource_tags = registry.tags
            report.region = registry.region
            report.status = "PASS"
            report.status_extended = f"EventBridge schema registry {registry.name} does not allow cross-account access."
            if is_policy_public(
                registry.policy,
                schema_client.audited_account,
                is_cross_account_allowed=False,
            ):
                report.status = "FAIL"
                report.status_extended = f"EventBridge schema registry {registry.name} allows cross-account access."

            findings.append(report)

        return findings
