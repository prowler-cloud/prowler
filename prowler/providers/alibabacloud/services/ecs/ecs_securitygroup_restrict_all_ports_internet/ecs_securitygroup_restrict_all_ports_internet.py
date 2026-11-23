from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.ecs.lib.security_groups import (
    is_public_ingress_exposing_all_ports,
)


class ecs_securitygroup_restrict_all_ports_internet(Check):
    """Check if security groups restrict all-port access from the internet."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []
        for security_group in ecs_client.security_groups.values():
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=security_group
            )
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not have all ports open to the internet."

            if not security_group.ingress_rules_complete:
                report.status = "MANUAL"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) could not be fully evaluated because its ingress rules were not completely retrieved from Alibaba Cloud."
            elif is_public_ingress_exposing_all_ports(security_group.ingress_rules):
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) has all ports open to the internet (0.0.0.0/0 or ::/0)."
                ecs_client.set_failed_check(self.__class__.__name__, security_group.arn)

            findings.append(report)
        return findings
