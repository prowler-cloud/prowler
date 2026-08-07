from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.sfs.sfs_client import sfs_client


class sfs_file_system_encryption(Check):
    """Check if SFS Turbo file systems have encryption enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for share in sfs_client.shares:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=share,
            )
            report.region = share.region
            report.resource_id = share.share_id
            report.resource_arn = f"huaweicloud:sfs:{share.region}:{sfs_client.audited_account}:share/{share.share_id}"

            if share.crypt_key_id:
                report.status = "PASS"
                report.status_extended = f"SFS Turbo file system '{share.name}' ({share.share_id}) has encryption enabled with KMS key '{share.crypt_key_id}'."
            else:
                report.status = "FAIL"
                report.status_extended = f"SFS Turbo file system '{share.name}' ({share.share_id}) does not have encryption enabled."

            findings.append(report)

        return findings
