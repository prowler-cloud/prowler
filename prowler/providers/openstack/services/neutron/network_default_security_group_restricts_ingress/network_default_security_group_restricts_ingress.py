from typing import List, Optional

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.neutron.neutron_client import neutron_client
from prowler.providers.openstack.services.neutron.neutron_service import SecurityGroup


class openstack_network_default_security_group_restricts_ingress(Check):
    """Ensure the default security group does not allow Internet-ingress."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []
        default_groups = [
            sg for sg in neutron_client.security_groups if sg.name == "default"
        ]

        if not default_groups:
            placeholder = SecurityGroup(
                id="default",
                name="default",
                project_id=neutron_client.project_id,
                region=neutron_client.region,
                rules=[],
            )
            findings.append(
                self._build_pass_report(
                    placeholder, "Default security group not found."
                )
            )
            return findings

        for sg in default_groups:
            risky_prefix = self._find_open_ingress_rule(sg)
            if risky_prefix:
                report = CheckReportOpenStack(metadata=self.metadata(), resource=sg)
                report.status = "FAIL"
                report.status_extended = f"Default security group {sg.id} allows ingress from {risky_prefix}."
            else:
                report = self._build_pass_report(
                    sg,
                    f"Default security group {sg.id} does not allow ingress from the Internet.",
                )

            findings.append(report)

        return findings

    def _build_pass_report(
        self, sg: SecurityGroup, message: str
    ) -> CheckReportOpenStack:
        report = CheckReportOpenStack(metadata=self.metadata(), resource=sg)
        report.status = "PASS"
        report.status_extended = message
        return report

    @staticmethod
    def _find_open_ingress_rule(sg: SecurityGroup) -> Optional[str]:
        """Return the CIDR that exposes the SG if any."""
        for rule in sg.rules:
            if (rule.direction or "").lower() != "ingress":
                continue
            cidr = (rule.remote_ip_prefix or "").strip()
            if cidr in ("0.0.0.0/0", "::/0"):
                return cidr or "0.0.0.0/0"
        return None
