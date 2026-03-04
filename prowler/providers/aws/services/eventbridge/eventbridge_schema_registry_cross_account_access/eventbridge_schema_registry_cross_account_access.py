from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.schema_client import schema_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class eventbridge_schema_registry_cross_account_access(Check):
    def execute(self):
        findings = []
        trusted_account_ids = schema_client.audit_config.get("trusted_account_ids", [])
        for registry in schema_client.registries.values():
            if registry.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=registry)
            report.status = "PASS"
            report.status_extended = f"EventBridge schema registry {registry.name} does not allow cross-account access."
            if is_policy_public(
                registry.policy,
                schema_client.audited_account,
                is_cross_account_allowed=False,
                trusted_account_ids=trusted_account_ids,
            ):
                report.status = "FAIL"
                report.status_extended = f"EventBridge schema registry {registry.name} allows cross-account access."

            findings.append(report)

        return findings
