from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_dmarc_record_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # DMARC records are TXT records at _dmarc subdomain starting with "v=DMARC1"
            dmarc_records = [
                record
                for record in dns_client.records
                if record.zone_id == zone.id
                and record.type == "TXT"
                and record.name
                and record.name.startswith("_dmarc")
                and "V=DMARC1" in record.content.upper()
            ]

            if dmarc_records:
                report.status = "PASS"
                report.status_extended = f"DMARC record exists for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"No DMARC record found for zone {zone.name}."
            findings.append(report)

        return findings
