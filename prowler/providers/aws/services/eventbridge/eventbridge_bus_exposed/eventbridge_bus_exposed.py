from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eventbridge.eventbridge_client import (
    eventbridge_client,
)
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class eventbridge_bus_exposed(Check):
    def execute(self):
        findings = []
        for bus in eventbridge_client.buses.values():
<<<<<<< HEAD
            report = Check_Report_AWS(self.metadata())
=======
            if bus.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=bus)
>>>>>>> d1053375b (fix(aws): handle `AccessDenied` when retrieving resource policy (#6908))
            report.status = "PASS"
            report.status_extended = (
                f"EventBridge event bus {bus.name} is not exposed to everyone."
            )
            report.resource_id = bus.name
            report.resource_arn = bus.arn
            report.resource_tags = bus.tags
            report.region = bus.region
            if is_policy_public(bus.policy, eventbridge_client.audited_account):
                report.status = "FAIL"
                report.status_extended = (
                    f"EventBridge event bus {bus.name} is exposed to everyone."
                )
            findings.append(report)
        return findings
