from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_challenge_passage_configured(Check):
    """Ensure that Challenge Passage is configured between 15 and 45 minutes for Cloudflare zones.

    Challenge Passage (Challenge TTL) determines how long a visitor who has passed
    a security challenge can access the site before being challenged again. A value
    between 15 and 45 minutes balances security with user experience.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Challenge Passage configured check.

        Iterates through all Cloudflare zones and verifies that Challenge Passage
        is set between 15 and 45 minutes.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if Challenge
            Passage is between 15 and 45 minutes, or FAIL status otherwise.
        """
        findings = []
        min_minutes = 15
        max_minutes = 45

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )
            # API returns seconds, convert to minutes
            challenge_ttl_minutes = zone.settings.challenge_ttl // 60

            if min_minutes <= challenge_ttl_minutes <= max_minutes:
                report.status = "PASS"
                report.status_extended = f"Challenge Passage is set to {challenge_ttl_minutes} minutes for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Challenge Passage is set to {challenge_ttl_minutes} minutes for zone {zone.name} "
                    f"(recommended: between {min_minutes} and {max_minutes} minutes)."
                )
            findings.append(report)
        return findings
