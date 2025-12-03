from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_caa_record_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # CAA records restrict which CAs can issue certificates
            caa_records = [
                record
                for record in dns_client.records
                if record.zone.id == zone.id and record.type == "CAA"
            ]

            if caa_records:
                report.status = "PASS"
                report.status_extended = (
                    f"CAA record exists for zone {zone.name} "
                    f"({len(caa_records)} record(s))."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"No CAA record found for zone {zone.name}."
            findings.append(report)

        return findings
