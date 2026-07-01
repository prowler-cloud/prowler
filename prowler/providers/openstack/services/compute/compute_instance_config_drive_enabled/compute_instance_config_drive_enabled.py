from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_config_drive_enabled(Check):
    """Ensure compute instances have config drive enabled for secure metadata injection."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            if instance.has_config_drive:
                report.status = "PASS"
                report.status_extended = f"Instance {instance.name} ({instance.id}) has config drive enabled for secure metadata injection."
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) does not have config drive enabled (relies on metadata service)."

            findings.append(report)

        return findings
