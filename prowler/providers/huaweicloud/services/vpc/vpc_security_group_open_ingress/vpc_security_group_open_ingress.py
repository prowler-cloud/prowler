from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client
from prowler.providers.huaweicloud.services.vpc.vpc_service import (
    SENSITIVE_PORTS,
    rule_covers_port,
    rule_source_is_open,
)


class vpc_security_group_open_ingress(Check):
    """Check if VPC security groups allow open ingress on sensitive ports."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for sg in vpc_client.security_groups.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = f"huaweicloud:vpc:{sg.region}:{vpc_client.audited_account}:security-group/{sg.id}"

            open_sensitive_ports = set()
            for rule in sg.rules:
                if rule.direction != "ingress":
                    continue
                if not rule_source_is_open(rule):
                    continue
                for port in SENSITIVE_PORTS:
                    if rule_covers_port(rule, port):
                        open_sensitive_ports.add(port)

            if open_sensitive_ports:
                report.status = "FAIL"
                ports_str = ", ".join(str(p) for p in sorted(open_sensitive_ports))
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) allows open ingress "
                    f"on sensitive port(s): {ports_str}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) does not allow "
                    "open ingress on sensitive ports."
                )

            findings.append(report)

        return findings
