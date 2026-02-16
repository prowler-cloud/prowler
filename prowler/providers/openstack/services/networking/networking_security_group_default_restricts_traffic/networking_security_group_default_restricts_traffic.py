from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.networking.networking_client import (
    networking_client,
)


class networking_security_group_default_restricts_traffic(Check):
    """Ensure default security groups have not been modified with custom rules."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for sg in networking_client.security_groups:
            # Only check default security groups
            if not sg.is_default:
                continue

            report = CheckReportOpenStack(metadata=self.metadata(), resource=sg)
            report.resource_id = sg.id
            report.resource_name = sg.name
            report.region = sg.region

            # Default security groups should have minimal rules
            # In OpenStack, default SGs typically have 4 default rules:
            # - 2 egress rules (IPv4 and IPv6 allowing all outbound)
            # - 2 ingress rules allowing traffic from the same security group
            # Any additional rules indicate modification
            default_rule_count = 4

            if len(sg.security_group_rules) > default_rule_count:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default security group {sg.name} ({sg.id}) has been modified with "
                    f"{len(sg.security_group_rules)} custom rules. Default security groups should "
                    f"remain unmodified; create custom security groups instead."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Default security group {sg.name} ({sg.id}) has not been modified "
                    f"({len(sg.security_group_rules)} rules present)."
                )

            findings.append(report)

        return findings
