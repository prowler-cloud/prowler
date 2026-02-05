from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.network.network_client import (  # noqa: E501
    network_client,
)


class network_security_group_default_restricts_traffic(Check):
    """Ensure default security groups have not been modified with custom rules."""  # noqa: E501

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for sg in network_client.security_groups:
            # Only check default security groups
            if not sg.is_default:
                continue

            report = CheckReportOpenStack(
                metadata=self.metadata(), resource=sg
            )  # noqa: E501
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
                    f"Default security group {sg.name} ({sg.id}) has been modified with "  # noqa: E501
                    f"{len(sg.security_group_rules)} custom rules. Default security groups should "  # noqa: E501
                    f"remain unmodified; create custom security groups instead."  # noqa: E501
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Default security group {sg.name} ({sg.id}) has not been modified "  # noqa: E501
                    f"({len(sg.security_group_rules)} rules present)."
                )

            findings.append(report)

        return findings
