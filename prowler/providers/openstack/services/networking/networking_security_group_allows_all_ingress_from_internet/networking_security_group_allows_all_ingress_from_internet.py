from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.lib.security_groups import is_cidr_public
from prowler.providers.openstack.services.networking.networking_client import (
    networking_client,
)


class networking_security_group_allows_all_ingress_from_internet(Check):
    """Ensure security groups do not allow all ingress traffic from the Internet."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for sg in networking_client.security_groups:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=sg)
            report.resource_id = sg.id
            report.resource_name = sg.name
            report.region = sg.region

            all_ingress_exposed = False
            exposed_rules = []

            for rule in sg.security_group_rules:
                # Only match rules that allow ALL protocols AND ALL ports
                if rule.direction != "ingress":
                    continue
                if rule.protocol is not None:
                    continue
                if rule.port_range_min is not None or rule.port_range_max is not None:
                    continue

                # Check if from internet (0.0.0.0/0, ::/0, or None with no group)
                if rule.remote_group_id:
                    continue
                if rule.remote_ip_prefix:
                    if not is_cidr_public(rule.remote_ip_prefix, any_address=True):
                        continue
                # else: no prefix and no group means all IPs

                all_ingress_exposed = True
                cidr = rule.remote_ip_prefix or "0.0.0.0/0"
                exposed_rules.append(f"rule {rule.id} ({cidr})")

            if all_ingress_exposed:
                report.status = "FAIL"
                rules_str = ", ".join(exposed_rules)
                report.status_extended = f"Security group {sg.name} ({sg.id}) allows all ingress traffic (any protocol, any port) from the Internet via {rules_str}."
            else:
                report.status = "PASS"
                report.status_extended = f"Security group {sg.name} ({sg.id}) does not allow all ingress traffic from the Internet."

            findings.append(report)

        return findings
