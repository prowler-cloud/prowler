from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client

# The Cloudflare Managed Ruleset (Pro+ plans) provides comprehensive WAF
# protection.  The Free Managed Ruleset (always active on all plans) is
# excluded because it cannot be disabled or configured.
# OWASP Core Ruleset coverage is handled by zone_waf_owasp_ruleset_enabled.
CLOUDFLARE_MANAGED_RULESET_ID = "efb7b8c949ac4650a09736fc376e9aee"


class zone_waf_enabled(Check):
    """Ensure that the Cloudflare Managed WAF Ruleset is enabled for zones.

    The Cloudflare Managed Ruleset protects against common web vulnerabilities
    including SQL injection, cross-site scripting (XSS), and other threats.
    It requires a Pro, Business, or Enterprise plan.

    The Free Managed Ruleset (available on all plans, always active) is excluded
    because it provides only basic protection and cannot be configured.

    OWASP Core Ruleset coverage is handled separately by
    ``zone_waf_owasp_ruleset_enabled``.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the WAF enabled check.

        Iterates through all Cloudflare zones and verifies that the Cloudflare
        Managed Ruleset (``efb7b8c949ac4650a09736fc376e9aee``) is deployed and
        has at least one enabled rule.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if the
            Cloudflare Managed Ruleset is active, or FAIL otherwise.
        """
        findings = []
        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            waf_enabled = False
            for waf_ruleset in zone.waf_rulesets:
                for rule in waf_ruleset.rules:
                    if (
                        rule.enabled
                        and rule.managed_ruleset_id == CLOUDFLARE_MANAGED_RULESET_ID
                    ):
                        waf_enabled = True
                        break
                if waf_enabled:
                    break

            if waf_enabled:
                report.status = "PASS"
                report.status_extended = f"WAF is enabled for zone {zone.name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"WAF is not enabled for zone {zone.name}."
            findings.append(report)
        return findings
