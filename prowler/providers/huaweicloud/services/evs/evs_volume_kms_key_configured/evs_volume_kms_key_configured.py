from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.evs.evs_client import evs_client


class evs_volume_kms_key_configured(Check):
    """Check if encrypted EVS volumes have a KMS key ID configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for volume in evs_client.volumes:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=volume)
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = (
                f"huaweicloud:evs:{volume.region}:"
                f"{evs_client.audited_account}:volume/{volume.id}"
            )

            if volume.is_encrypted and volume.kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"EVS volume {volume.name} ({volume.id}) is encrypted "
                    f"with KMS key {volume.kms_key_id}."
                )
            elif volume.is_encrypted and not volume.kms_key_id:
                report.status = "FAIL"
                report.status_extended = (
                    f"EVS volume {volume.name} ({volume.id}) is encrypted "
                    f"but does not have a KMS key ID configured."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"EVS volume {volume.name} ({volume.id}) is not encrypted, "
                    f"KMS key check not applicable."
                )

            findings.append(report)

        return findings
