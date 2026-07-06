from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


def _is_open_network(value: str | None) -> bool:
    if value is None:
        return False
    normalized = str(value).lower().strip()
    return normalized in ("any", "0.0.0.0/0", "::/0")


def _is_permissive_inbound(rule) -> bool:
    if (rule.rule_type or "").lower() != "inbound":
        return False
    if (rule.protocol_name or "").lower() != "all":
        return False
    return _is_open_network(rule.network) or _is_open_network(rule.network_cidr)


class securitygroup_no_inbound_any_all_ports(Check):
    """Check if E2E Networks security groups do not allow inbound all-protocol traffic from any source."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for group in securitygroup_client.security_groups:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=group)
            report.status = "PASS"
            report.status_extended = f"Security group {group.name} does not allow inbound all-protocol traffic from any source."
            if any(_is_permissive_inbound(rule) for rule in group.rules):
                report.status = "FAIL"
                report.status_extended = f"Security group {group.name} allows inbound all-protocol traffic from any source."
            findings.append(report)
        return findings
