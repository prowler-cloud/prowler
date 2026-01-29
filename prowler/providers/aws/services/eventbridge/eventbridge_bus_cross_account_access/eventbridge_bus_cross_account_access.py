from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.eventbridge_client import (
    eventbridge_client,
)
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class eventbridge_bus_cross_account_access(Check):
    def execute(self):
        findings = []
        trusted_account_ids = eventbridge_client.audit_config.get(
            "trusted_account_ids", []
        )
        for bus in eventbridge_client.buses.values():
            if bus.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=bus)
            report.status = "PASS"
            report.status_extended = (
                f"EventBridge event bus {bus.name} does not allow cross-account access."
            )
            if is_policy_public(
                bus.policy,
                eventbridge_client.audited_account,
                is_cross_account_allowed=False,
                trusted_account_ids=trusted_account_ids,
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"EventBridge event bus {bus.name} allows cross-account access."
                )

            findings.append(report)

        return findings
