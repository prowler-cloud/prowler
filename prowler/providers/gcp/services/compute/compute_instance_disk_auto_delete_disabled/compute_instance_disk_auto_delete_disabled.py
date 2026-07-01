from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_disk_auto_delete_disabled(Check):
    """
    Ensure that VM instance attached disks have auto-delete disabled.

    This check verifies whether GCP Compute Engine VM instances have auto-delete
    disabled for their attached persistent disks to prevent accidental data loss
    when the instance is terminated.

    - PASS: All attached disks have auto-delete disabled.
    - FAIL: One or more attached disks have auto-delete enabled.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_GCP(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = f"VM Instance {instance.name} has auto-delete disabled for all attached disks."

            auto_delete_disks = [
                disk.name for disk in instance.disks if disk.auto_delete
            ]

            if auto_delete_disks:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} has auto-delete enabled for the following disks: {', '.join(auto_delete_disks)}."

            findings.append(report)

        return findings
