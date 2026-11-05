from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


class securitygroup_no_all_traffic_rule(Check):
    """Check that security groups do not allow all traffic."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for group in securitygroup_client.security_groups:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=group)
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
