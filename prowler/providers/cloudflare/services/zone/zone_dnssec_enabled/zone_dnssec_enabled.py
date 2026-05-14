from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_dnssec_enabled(Check):
    """Ensure that DNSSEC is enabled for Cloudflare zones.

    DNSSEC (Domain Name System Security Extensions) adds cryptographic signatures
    to DNS records, protecting against DNS spoofing and cache poisoning attacks.
    When enabled, it ensures that DNS responses are authentic and have not been
    tampered with during transit.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the DNSSEC enabled check.

        Iterates through all Cloudflare zones and verifies that DNSSEC status
        is set to 'active'. A zone passes the check if DNSSEC is actively
        protecting its DNS records; otherwise, it fails.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if DNSSEC
            is active, or FAIL status if DNSSEC is not enabled for the zone.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            if zone.dnssec_status == "active":
                report.status = "PASS"
                report.status_extended = f"DNSSEC is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"DNSSEC is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
