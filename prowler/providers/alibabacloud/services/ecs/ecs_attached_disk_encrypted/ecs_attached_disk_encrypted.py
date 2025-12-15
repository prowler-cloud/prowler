from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_attached_disk_encrypted(Check):
    """Check if attached disks are encrypted."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for disk in ecs_client.disks:
            # Only check attached disks
            if disk.is_attached:
                report = CheckReportAlibabaCloud(
                    metadata=self.metadata(), resource=disk
                )
                report.region = disk.region
                report.resource_id = disk.id
                report.resource_arn = (
                    f"acs:ecs:{disk.region}:{ecs_client.audited_account}:disk/{disk.id}"
                )

                if disk.is_encrypted:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Disk {disk.name if disk.name else disk.id} attached to instance "
                        f"{disk.attached_instance_id} is encrypted."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Disk {disk.name if disk.name else disk.id} attached to instance "
                        f"{disk.attached_instance_id} is not encrypted."
                    )

                findings.append(report)

        return findings
