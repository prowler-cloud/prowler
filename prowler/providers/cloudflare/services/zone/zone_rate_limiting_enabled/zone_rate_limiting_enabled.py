from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_rate_limiting_enabled(Check):
    """Ensure that Rate Limiting is configured for Cloudflare zones.

    Rate Limiting protects against DDoS attacks, brute force attempts, and API
    abuse by limiting the number of requests from a single source within a specified
    time window. Rules are configured in the http_ratelimit phase and help maintain
    service availability under high-traffic conditions.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the Rate Limiting enabled check.

        Iterates through all Cloudflare zones and verifies that at least one
        enabled rate limiting rule exists.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if rate
            limiting rules are configured, or FAIL status if no rules exist.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Get enabled rate limiting rules for this zone
            enabled_rules = [rule for rule in zone.rate_limit_rules if rule.enabled]

            if enabled_rules:
                report.status = "PASS"
                rules_str = ", ".join(
                    rule.description or rule.id for rule in enabled_rules
                )
                report.status_extended = (
                    f"Rate limiting is configured for zone {zone.name}: {rules_str}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"No rate limiting rules configured for zone {zone.name}."
                )
            findings.append(report)

        return findings
