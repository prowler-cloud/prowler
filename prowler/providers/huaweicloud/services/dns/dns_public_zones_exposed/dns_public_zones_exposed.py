from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.dns.dns_client import dns_client


class dns_public_zones_exposed(Check):
    """Check if public DNS zones may expose internal infrastructure."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for zone in dns_client.public_zones:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=zone,
            )
            report.region = zone.region
            report.resource_id = zone.id
            report.resource_arn = f"huaweicloud:dns:{zone.region}:{dns_client.audited_account}:zone/{zone.id}"

            report.status = "FAIL"
            report.status_extended = (
                f"Public DNS zone '{zone.name}' ({zone.id}) has {zone.record_num} records. "
                f"Verify that it does not expose internal infrastructure."
            )

            findings.append(report)

        return findings
