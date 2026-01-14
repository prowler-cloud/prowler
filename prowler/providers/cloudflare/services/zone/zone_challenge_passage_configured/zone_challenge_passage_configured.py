from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_challenge_passage_configured(Check):
    """Ensure that Challenge Passage is configured appropriately for Cloudflare zones.

    Challenge Passage (Challenge TTL) determines how long a visitor who has passed
    a security challenge can access the site before being challenged again. A value
    of 1 hour (3600 seconds) balances security with user experience, requiring
    re-verification periodically without excessive friction for legitimate users.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Challenge Passage configured check.

        Iterates through all Cloudflare zones and verifies that Challenge Passage
        is set to the recommended value of 1 hour (3600 seconds). This balances
        security requirements with user experience.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Challenge
            Passage is set to 3600 seconds, or FAIL status if it differs.
        """
        findings = []
        # Recommended challenge TTL is 1 hour (3600 seconds)
        recommended_ttl = 3600

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            challenge_ttl = zone.settings.challenge_ttl or 0
            if challenge_ttl == recommended_ttl:
                report.status = "PASS"
                report.status_extended = f"Challenge Passage is set to {challenge_ttl} seconds for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Challenge Passage is set to {challenge_ttl} seconds for zone {zone.name} "
                    f"(recommended: {recommended_ttl})."
                )
            findings.append(report)
        return findings
