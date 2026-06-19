from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


def _is_permissive_inbound(rule) -> bool:
    return (
        rule.rule_type.lower() == "inbound"
        and rule.protocol_name.lower() == "all"
        and rule.network.lower() == "any"
    )


class securitygroup_no_inbound_any_all_ports(Check):
    def execute(self):
        findings = []
        for group in securitygroup_client.security_groups:
            report = CheckReportE2e(metadata=self.metadata(), resource=group)
            report.status = "PASS"
            report.status_extended = (
                f"Security group {group.name} does not allow inbound all-protocol traffic from any source."
            )
            if any(_is_permissive_inbound(rule) for rule in group.rules):
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {group.name} allows inbound all-protocol traffic from any source."
                )
            findings.append(report)
        return findings
