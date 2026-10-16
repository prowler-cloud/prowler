from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cbr.cbr_client import cbr_client


class cbr_vault_resources(Check):
    """Check if CBR vaults have resources associated."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for vault in cbr_client.vaults:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=vault,
            )
            report.region = vault.region
            report.resource_id = vault.vault_id
            report.resource_arn = f"huaweicloud:cbr:{vault.region}:{cbr_client.audited_account}:vault/{vault.vault_id}"

            if vault.resources:
                report.status = "PASS"
                report.status_extended = f"CBR vault '{vault.name}' ({vault.vault_id}) has {len(vault.resources)} resource(s) associated."
            else:
                report.status = "FAIL"
                report.status_extended = f"CBR vault '{vault.name}' ({vault.vault_id}) has no resources associated."

            findings.append(report)

        return findings
