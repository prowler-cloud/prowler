from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


class zones_waf_owasp_ruleset_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for zone in zones_client.zones.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=zone,
            )

            # Find OWASP managed rulesets for this zone
            owasp_rulesets = [
                ruleset
                for ruleset in zone.waf_rulesets
                if (
                    "owasp" in (ruleset.name or "").lower()
                    or ruleset.phase == "http_request_firewall_managed"
                )
            ]

            if owasp_rulesets:
                report.status = "PASS"
                report.status_extended = (
                    f"Zone {zone.name} has OWASP managed WAF ruleset enabled "
                    f"({len(owasp_rulesets)} ruleset(s))."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Zone {zone.name} does not have OWASP managed WAF ruleset enabled."
                )
            findings.append(report)

        return findings
