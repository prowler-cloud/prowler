import re

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_record_caa_exists(Check):
    """Ensure that CAA record exists with certificate issuance restrictions.

    CAA (Certificate Authority Authorization) is a DNS record type that allows
    domain owners to specify which certificate authorities (CAs) are permitted
    to issue SSL/TLS certificates for their domain. This check verifies that CAA
    records exist with "issue" or "issuewild" tags that explicitly authorize
    specific CAs, preventing unauthorized certificate issuance and reducing the
    risk of man-in-the-middle attacks from fraudulent certificates.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the CAA record exists check.

        Iterates through all Cloudflare zones and verifies CAA configuration.
        The check validates two conditions:
        1. CAA records exist for the zone
        2. At least one record has an "issue" or "issuewild" tag specifying authorized CAs

        Returns:
            A list of CheckReportCloudflare objects with PASS status if CAA
            records with issuance restrictions exist, or FAIL status if no CAA
            records are found or they lack proper issue/issuewild tags.
        """
        findings = []

        for zone in zone_client.zones.values():
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

            if not caa_records:
                report.status = "FAIL"
                report.status_extended = f"No CAA record found for zone {zone.name}."
            else:
                # Check if CAA records have issue or issuewild tags with CA specified
                issue_records = [
                    record
                    for record in caa_records
                    if self._has_issue_tag_with_ca(record.content)
                ]

                records_str = ", ".join(record.name for record in caa_records)

                if issue_records:
                    report.status = "PASS"
                    report.status_extended = f"CAA record with certificate issuance restrictions exists for zone {zone.name}: {records_str}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"CAA record exists for zone {zone.name} but does not specify authorized CAs with issue or issuewild tags: {records_str}."

            findings.append(report)

        return findings

    def _has_issue_tag_with_ca(self, content: str) -> bool:
        """Check if CAA record has issue or issuewild tag with a CA specified.

        CAA content format: "flags tag value" e.g., "0 issue letsencrypt.org"
        """
        # Strip quotes that may be present from Cloudflare API
        content_lower = content.strip('"').lower()
        # Match issue or issuewild tag followed by a value (CA name or ";" to block all)
        # Format: "0 issue letsencrypt.org" or "0 issuewild ;" or "0 issue \"digicert.com\""
        issue_match = re.search(r"\bissue\b", content_lower)
        issuewild_match = re.search(r"\bissuewild\b", content_lower)
        return bool(issue_match or issuewild_match)
