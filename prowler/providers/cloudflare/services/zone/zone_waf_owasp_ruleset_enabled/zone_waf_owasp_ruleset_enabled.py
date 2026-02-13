from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class zone_waf_owasp_ruleset_enabled(Check):
    """Ensure that OWASP managed WAF rulesets are enabled for Cloudflare zones.

    The OWASP Core Ruleset provides protection against common web application
    vulnerabilities including SQL injection, cross-site scripting (XSS), and other
    OWASP Top 10 threats. These managed rulesets are essential for defense in depth
    and protecting applications from well-known attack vectors.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Execute the OWASP WAF ruleset enabled check.

        Iterates through all Cloudflare zones and verifies that OWASP managed
        WAF rulesets are enabled. The check identifies OWASP rulesets by name
        containing "owasp" or by the http_request_firewall_managed phase.

        Returns:
            A list of CheckReportCloudflare objects with PASS status if OWASP
            rulesets are enabled, or FAIL status if no OWASP protection exists.
        """
        findings = []

        for zone in zone_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Find OWASP managed rulesets for this zone
            # Only match rulesets that explicitly contain "owasp" in the name
            # The phase check was too broad as it matched any managed ruleset
            owasp_rulesets = [
                ruleset
                for ruleset in zone.waf_rulesets
                if "owasp" in (ruleset.name or "").lower()
            ]

            if owasp_rulesets:
                report.status = "PASS"
                ruleset_descriptions = ", ".join(
                    ruleset.name for ruleset in owasp_rulesets
                )
                report.status_extended = (
                    f"Zone {zone.name} has OWASP managed WAF ruleset enabled: "
                    f"{ruleset_descriptions}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} does not have OWASP managed WAF ruleset enabled."
                )
            findings.append(report)

        return findings
