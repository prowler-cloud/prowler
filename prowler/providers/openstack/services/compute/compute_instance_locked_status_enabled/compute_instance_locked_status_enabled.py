from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_locked_status_enabled(Check):
    """Ensure compute instances have locked status enabled to prevent unauthorized operations."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            if instance.is_locked:
                report.status = "PASS"
                reason = (
                    f" (reason: {instance.locked_reason})"
                    if instance.locked_reason
                    else ""
                )
                report.status_extended = f"Instance {instance.name} ({instance.id}) has locked status enabled{reason}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) does not have locked status enabled."

            findings.append(report)

        return findings
