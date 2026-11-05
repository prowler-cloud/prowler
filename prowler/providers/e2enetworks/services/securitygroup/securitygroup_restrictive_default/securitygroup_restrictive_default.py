from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


def _is_open_network(value: str | None) -> bool:
    if value is None:
        return False
    normalized = str(value).lower().strip()
    return normalized in ("any", "0.0.0.0/0", "::/0")


def _has_permissive_inbound(rules) -> bool:
    for rule in rules:
        if (
            (rule.rule_type or "").lower() == "inbound"
            and (rule.protocol_name or "").lower() == "all"
            and (_is_open_network(rule.network) or _is_open_network(rule.network_cidr))
        ):
            return True
    return False


class securitygroup_restrictive_default(Check):
    """Check if E2E Networks nodes do not rely on permissive default security groups."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        node_groups: dict[str, list] = {}
        for group in securitygroup_client.node_security_groups:
            node_groups.setdefault(group.node_id, []).append(group)

        for node_id, groups in node_groups.items():
            resource = groups[0]
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=resource)
            report.status = "PASS"
            report.status_extended = f"Node {resource.node_name} does not rely on a permissive default security group."

            default_groups = [group for group in groups if group.is_default]
            if default_groups and len(groups) == len(default_groups):
                if any(
                    _has_permissive_inbound(group.rules) for group in default_groups
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Node {resource.node_name} uses only default security groups with overly permissive inbound rules."

            findings.append(report)
        return findings
