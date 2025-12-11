from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_spf_record_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # SPF records are TXT records starting with "v=spf1"
            spf_records = [
                record
                for record in dns_client.records
                if record.zone.id == zone.id
                and record.type == "TXT"
                and record.content.startswith("v=spf1")
            ]

            if spf_records:
                report.status = "PASS"
                report.status_extended = f"SPF record exists for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"No SPF record found for zone {zone.name}."
            findings.append(report)

        return findings
