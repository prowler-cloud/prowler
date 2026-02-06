from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.lib.security_groups import (
    check_security_group_rule,
)
from prowler.providers.openstack.services.network.network_client import (
    network_client,
)


class network_security_group_allows_rdp_from_internet(Check):
    """Ensure security groups do not allow RDP from the Internet."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for sg in network_client.security_groups:
            report = CheckReportOpenStack(
                metadata=self.metadata(), resource=sg
            )
            report.resource_id = sg.id
            report.resource_name = sg.name
            report.region = sg.region

            # Check if any rule allows RDP from 0.0.0.0/0 or ::/0
            rdp_exposed = False
            exposed_rules = []

            for rule in sg.security_group_rules:
                if check_security_group_rule(
                    rule=rule,
                    protocol="tcp",
                    ports=[3389],
                    any_address=True,
                    direction="ingress",
                ):
                    rdp_exposed = True
                    cidr = rule.remote_ip_prefix or "0.0.0.0/0"
                    exposed_rules.append(
                        f"rule {rule.id} ({rule.protocol}/{cidr}:{rule.port_range_min}-{rule.port_range_max})"
                    )

            if rdp_exposed:
                report.status = "FAIL"
                rules_str = ", ".join(exposed_rules)
                report.status_extended = f"Security group {sg.name} ({sg.id}) allows unrestricted RDP access (port 3389) from the Internet via {rules_str}."
            else:
                report.status = "PASS"
                report.status_extended = f"Security group {sg.name} ({sg.id}) does not allow RDP (port 3389) from the Internet."

            findings.append(report)

        return findings
