from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client

OWASP_CORE_RULESET_ID = "4814384a9e5d4991b9815dcfc25d2f1f"


class zone_waf_owasp_ruleset_enabled(Check):
    """Ensure that OWASP managed WAF rulesets are enabled for Cloudflare zones.

    The OWASP Core Ruleset provides protection against common web application
    vulnerabilities including SQL injection, cross-site scripting (XSS), and other
    OWASP Top 10 threats. These managed rulesets are essential for defense in depth
    and protecting applications from well-known attack vectors.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the OWASP WAF ruleset enabled check.

        Iterates through all Cloudflare zones and verifies that the OWASP Core
        Ruleset (``4814384a9e5d4991b9815dcfc25d2f1f``) is deployed and enabled.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if OWASP
            ruleset is enabled, or FAIL status if no OWASP protection exists.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Find enabled OWASP rules by matching the well-known
            # managed ruleset ID across all WAF entrypoint rulesets.
            owasp_enabled = False
            for waf_ruleset in zone.waf_rulesets:
                for rule in waf_ruleset.rules:
                    if (
                        rule.enabled
                        and rule.managed_ruleset_id == OWASP_CORE_RULESET_ID
                    ):
                        owasp_enabled = True
                        break
                if owasp_enabled:
                    break

            if owasp_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {zone.name} has OWASP managed WAF ruleset enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} does not have OWASP managed WAF ruleset enabled."
                )
            findings.append(report)

        return findings
