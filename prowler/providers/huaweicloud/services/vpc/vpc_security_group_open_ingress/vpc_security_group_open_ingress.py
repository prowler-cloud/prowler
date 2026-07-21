from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client

SENSITIVE_PORTS = {22, 3389, 3306, 6379, 27017}


class vpc_security_group_open_ingress(Check):
    """Check if VPC security groups allow open ingress (0.0.0.0/0) on sensitive ports."""

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
                if rule.remote_ip_prefix not in ("0.0.0.0/0", "::/0"):
                    continue
                if rule.port_range_min is not None and rule.port_range_max is not None:
                    for port in range(rule.port_range_min, rule.port_range_max + 1):
                        if port in SENSITIVE_PORTS:
                            open_sensitive_ports.add(port)
                elif rule.port_range_min is not None:
                    if rule.port_range_min in SENSITIVE_PORTS:
                        open_sensitive_ports.add(rule.port_range_min)

            if open_sensitive_ports:
                report.status = "FAIL"
                ports_str = ", ".join(str(p) for p in sorted(open_sensitive_ports))
                report.status_extended = f"Security group {sg.name} ({sg.id}) allows open ingress (0.0.0.0/0) on sensitive port(s): {ports_str}."
            else:
                report.status = "PASS"
                report.status_extended = f"Security group {sg.name} ({sg.id}) does not allow open ingress on sensitive ports."

            findings.append(report)

        return findings
