from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_record_spf_exists(Check):
    """Ensure that SPF record exists with strict policy for Cloudflare zones.

    SPF (Sender Policy Framework) is an email authentication method that specifies
    which mail servers are authorized to send email on behalf of the domain. This
    check verifies that an SPF record exists as a TXT record starting with "v=spf1"
    and uses the strict policy qualifier "-all" to instruct receiving servers to
    reject emails from unauthorized sources.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the SPF record exists check.

        Iterates through all Cloudflare zones and verifies SPF configuration.
        The check validates two conditions:
        1. An SPF record exists (TXT record starting with "v=spf1")
        2. The record uses strict policy "-all" (not ~all, ?all, or +all)

        Returns:
            A list of CheckReportCloudflare objects with PASS status if an SPF
            record with strict policy exists, or FAIL status if no SPF record
            is found or it uses a permissive policy.
        """
        findings = []

        for zone in zone_client.zones.values():
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
