from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.evs.evs_client import evs_client


class evs_volume_encryption(Check):
    """Check if EVS volumes are encrypted."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for volume in evs_client.volumes:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=volume)
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = f"huaweicloud:evs:{volume.region}:{evs_client.audited_account}:volume/{volume.id}"

            if volume.is_encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"EVS volume {volume.name} ({volume.id}) is encrypted."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"EVS volume {volume.name} ({volume.id}) is not encrypted."
                )

            findings.append(report)

        return findings
