from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_disk_encryption_enabled(Check):
    def execute(self):
        findings = []
        for disk in ecs_client.disks.values():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=disk)
            report.status = "FAIL"
            report.status_extended = (
                f"ECS disk {disk.name} ({disk.id}) is not encrypted."
            )
            if disk.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"ECS disk {disk.name} ({disk.id}) is encrypted."
                )
            findings.append(report)
        return findings
