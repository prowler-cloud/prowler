import re

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_record_dmarc_exists(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zone_client.zones.values():
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
                and "V=DMARC1" in record.content.strip('"').upper()
            ]

            if not dmarc_records:
                report.status = "FAIL"
                report.status_extended = f"No DMARC record found for zone {zone.name}."
            else:
                # Check if DMARC uses enforcement policy (p=reject or p=quarantine) vs monitoring (p=none)
                enforcement_records = [
                    record
                    for record in dmarc_records
                    if self._get_policy_value(record.content)
                    in ("reject", "quarantine")
                ]

                records_str = ", ".join(record.name for record in dmarc_records)

                if enforcement_records:
                    # Get the actual policy value from the first enforcement record
                    policy = self._get_policy_value(enforcement_records[0].content)
                    report.status = "PASS"
                    report.status_extended = f"DMARC record with enforcement policy p={policy} exists for zone {zone.name}: {records_str}."
                else:
                    # Get the actual policy value to show in the message
                    policy = self._get_policy_value(dmarc_records[0].content) or "none"
                    report.status = "FAIL"
                    report.status_extended = f"DMARC record exists for zone {zone.name} but uses monitoring-only policy p={policy}: {records_str}."

            findings.append(report)

        return findings

    def _get_policy_value(self, content: str) -> str | None:
        """Extract the DMARC policy value (reject, quarantine, or none)."""
        # Strip quotes that may be present from Cloudflare API
        content_clean = content.strip('"')
        # Match p=<value> (with optional spaces around =)
        match = re.search(r"p\s*=\s*(\w+)", content_clean, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None
