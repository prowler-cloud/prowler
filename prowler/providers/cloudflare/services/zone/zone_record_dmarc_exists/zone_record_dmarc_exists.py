import re

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_record_dmarc_exists(Check):
    """Ensure that DMARC record exists with enforcement policy for Cloudflare zones.

    DMARC (Domain-based Message Authentication, Reporting, and Conformance) is an
    email authentication protocol that builds on SPF and DKIM. It allows domain
    owners to specify how receiving mail servers should handle emails that fail
    authentication checks. This check verifies that a DMARC record exists at the
    _dmarc subdomain with an enforcement policy (p=reject or p=quarantine) to
    actively block or quarantine spoofed emails, not just monitor them (p=none).
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the DMARC record exists check.

        Iterates through all Cloudflare zones and verifies DMARC configuration.
        The check validates two conditions:
        1. A DMARC record exists (TXT record at _dmarc subdomain with "v=DMARC1")
        2. The record uses an enforcement policy (p=reject or p=quarantine)

        Returns:
            A list of CheckReportCloudflare objects with PASS status if a DMARC
            record with enforcement policy exists, or FAIL status if no DMARC
            record is found or it uses monitoring-only policy (p=none).
        """
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
