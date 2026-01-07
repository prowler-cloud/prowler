from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_caa_record_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # CAA records restrict which CAs can issue certificates
            caa_records = [
                record
                for record in dns_client.records
                if record.zone_id == zone.id and record.type == "CAA"
            ]

            if caa_records:
                report.status = "PASS"
                # Extract CA names from CAA record content (format: "0 issue "ca.org"")
                ca_names = []
                for record in caa_records:
                    parts = record.content.split()
                    if len(parts) >= 3:
                        ca_names.append(parts[2].strip('"'))
                    else:
                        ca_names.append(record.content)
                report.status_extended = (
                    f"CAA record exists for zone {zone.name}: {', '.join(ca_names)}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"No CAA record found for zone {zone.name}."
            findings.append(report)

        return findings
