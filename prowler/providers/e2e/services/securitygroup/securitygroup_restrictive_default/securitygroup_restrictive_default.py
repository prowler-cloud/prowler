from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.securitygroup.securitygroup_client import (
    securitygroup_client,
)


def _has_permissive_inbound(rules) -> bool:
    for rule in rules:
        if (
            rule.rule_type.lower() == "inbound"
            and rule.protocol_name.lower() == "all"
            and rule.network.lower() == "any"
        ):
            return True
    return False


class securitygroup_restrictive_default(Check):
    def execute(self):
        findings = []
        node_groups: dict[str, list] = {}
        for group in securitygroup_client.node_security_groups:
            node_groups.setdefault(group.node_id, []).append(group)

        for node_id, groups in node_groups.items():
            resource = groups[0]
            report = CheckReportE2e(metadata=self.metadata(), resource=resource)
            report.status = "PASS"
            report.status_extended = (
                f"Node {resource.node_name} does not rely on a permissive default security group."
            )

            default_groups = [group for group in groups if group.is_default]
            if default_groups and len(groups) == len(default_groups):
                if any(_has_permissive_inbound(group.rules) for group in default_groups):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Node {resource.node_name} uses only default security groups with overly permissive inbound rules."
                    )

            findings.append(report)
        return findings
