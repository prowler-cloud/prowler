from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_security_under_attack_disabled(Check):
    """Ensure that Under Attack Mode is disabled during normal operations.

    Under Attack Mode is a DDoS mitigation feature that performs additional
    security checks including an interstitial JavaScript challenge page for all
    visitors. While effective during active attacks, it significantly impacts
    user experience and should only be enabled temporarily during actual DDoS
    incidents, not as a permanent security measure.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Under Attack Mode disabled check.

        Iterates through all Cloudflare zones and verifies that the security
        level is not set to "under_attack". Having this mode permanently enabled
        indicates either an ongoing attack or misconfiguration that degrades
        user experience unnecessarily.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Under
            Attack Mode is disabled, or FAIL status if it is currently enabled.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            security_level = (zone.settings.security_level or "").lower()

            if security_level == "under_attack":
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} has Under Attack Mode enabled."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {zone.name} does not have Under Attack Mode enabled."
                )
            findings.append(report)
        return findings
