from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_security_groups_attached(Check):
    """Ensure compute instances have security groups attached."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            if instance.security_groups:
                report.status = "PASS"
                sg_names = ", ".join(instance.security_groups)
                report.status_extended = f"Instance {instance.name} ({instance.id}) has security groups attached: {sg_names}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) does not have any security groups attached."

            findings.append(report)

        return findings
