from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.waf.waf_client import waf_client


class waf_owasp_enabled(Check):
    def execute(self) -> list[CheckReportCloudflare]:
        findings = []

        for ruleset in waf_client.rulesets:
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=ruleset,
                zone=ruleset.zone,
            )

            # Check if this is an OWASP managed ruleset
            is_owasp = (
                "owasp" in (ruleset.name or "").lower()
                or ruleset.phase == "http_request_firewall_managed"
            )

            if is_owasp:
                report.status = "PASS"
                report.status_extended = (
                    f"WAF ruleset '{ruleset.name}' is an OWASP managed ruleset."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"WAF ruleset '{ruleset.name}' is not an OWASP managed ruleset."
                )
            findings.append(report)

        return findings
