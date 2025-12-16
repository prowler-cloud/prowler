from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_challenge_passage_configured(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        # Recommended challenge TTL is 1 hour (3600 seconds)
        recommended_ttl = 3600

        for zone in zones_client.zones.values():
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
