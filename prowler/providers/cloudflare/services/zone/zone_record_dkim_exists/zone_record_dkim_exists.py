import base64
import re

from cryptography.hazmat.primitives.serialization import load_der_public_key

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_record_dkim_exists(Check):
    """Ensure that DKIM record exists with valid public key for Cloudflare zones.

    DKIM (DomainKeys Identified Mail) is an email authentication method that allows
    the receiver to verify that an email was sent by the domain owner and was not
    modified in transit. This check verifies that DKIM records exist at *._domainkey
    subdomains containing "v=DKIM1" with a cryptographically valid public key in the
    p= parameter that can be used to verify email signatures.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the DKIM record exists check.

        Iterates through all Cloudflare zones and verifies DKIM configuration.
        The check validates three conditions:
        1. A DKIM record exists (TXT record at *._domainkey with "v=DKIM1")
        2. The record contains a p= parameter with a public key
        3. The public key is cryptographically valid (valid Base64 and DER format)

        Returns:
            A list of CheckReportCloudflare objects with PASS status if a DKIM
            record with valid public key exists, or FAIL status if no DKIM record
            is found or the public key is invalid/missing.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # DKIM records are TXT records at *._domainkey subdomain containing "v=DKIM1"
            dkim_records = [
                record
                for record in dns_client.records
                if record.zone_id == zone.id
                and record.type == "TXT"
                and record.name
                and "_domainkey" in record.name
                and "V=DKIM1"
                in record.content.replace('" "', "").replace('"', "").upper()
            ]

            if not dkim_records:
                report.status = "FAIL"
                report.status_extended = f"No DKIM record found for zone {zone.name}."
            else:
                # Check if DKIM records have a valid public key
                valid_key_records = [
                    record
                    for record in dkim_records
                    if self._has_valid_public_key(record.content)
                ]

                records_str = ", ".join(record.name for record in dkim_records)

                if valid_key_records:
                    report.status = "PASS"
                    report.status_extended = f"DKIM record with valid public key exists for zone {zone.name}: {records_str}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"DKIM record exists for zone {zone.name} but has invalid or missing public key: {records_str}."

            findings.append(report)

        return findings

    def _has_valid_public_key(self, content: str) -> bool:
        """Check if DKIM record has a valid public key.

        Validates that:
        1. The p= parameter exists and is not empty
        2. The key is valid Base64
        3. The key can be loaded as a valid DER-encoded public key
        """
        # Cloudflare API may return TXT records with quotes, and long records
        # may be split into multiple quoted strings like: "part1" "part2"
        # First remove '" "' to join split parts, then remove remaining quotes
        content = content.replace('" "', "").replace('"', "")

        # Extract the public key value from p= parameter
        match = re.search(r"p\s*=\s*([^;\s]*)", content, re.IGNORECASE)
        if not match:
            return False

        key_value = match.group(1)

        # Empty key means revoked
        if not key_value:
            return False

        try:
            # Add padding if necessary for Base64 decoding
            padding = 4 - (len(key_value) % 4)
            if padding != 4:
                key_value += "=" * padding

            # Decode Base64 to get DER-encoded key
            der_key = base64.b64decode(key_value, validate=True)

            # Try to load as a public key using cryptography library
            load_der_public_key(der_key)
            return True
        except Exception:
            return False
