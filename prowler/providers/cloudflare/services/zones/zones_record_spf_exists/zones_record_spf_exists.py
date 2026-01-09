from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_record_spf_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # SPF records are TXT records starting with "v=spf1"
            spf_records = [
                record
                for record in dns_client.records
                if record.zone_id == zone.id
                and record.type == "TXT"
                and record.content.strip('"').startswith("v=spf1")
            ]

            if not spf_records:
                report.status = "FAIL"
                report.status_extended = f"No SPF record found for zone {zone.name}."
            else:
                # Check if SPF uses strict policy (-all) vs permissive (~all, ?all, +all)
                strict_records = [
                    record
                    for record in spf_records
                    if record.content.strip('"').rstrip().endswith("-all")
                ]

                records_str = ", ".join(record.name for record in spf_records)

                if strict_records:
                    report.status = "PASS"
                    report.status_extended = f"SPF record with strict policy -all exists for zone {zone.name}: {records_str}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SPF record exists for zone {zone.name} but does not use strict policy -all: {records_str}."

            findings.append(report)

        return findings
