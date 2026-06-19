from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


class securitygroup_no_all_traffic_rule(Check):
    def execute(self):
        findings = []
        for group in securitygroup_client.security_groups:
            report = CheckReportE2e(metadata=self.metadata(), resource=group)
            report.status = "PASS"
            report.status_extended = (
                f"Security group {group.name} does not allow all traffic."
            )
            if group.is_all_traffic_rule:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {group.name} allows all traffic."
                )
            findings.append(report)
        return findings
