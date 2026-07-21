from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client


class vpc_security_group_all_protocols_open(Check):
    """Check if VPC security groups allow all protocols (any port) from 0.0.0.0/0 on ingress."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for sg in vpc_client.security_groups.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = f"huaweicloud:vpc:{sg.region}:{vpc_client.audited_account}:security-group/{sg.id}"

            all_protocol_rules = []
            for rule in sg.rules:
                if rule.direction != "ingress":
                    continue
                if rule.remote_ip_prefix not in ("0.0.0.0/0", "::/0"):
                    continue
                if rule.port_range_min is None and rule.port_range_max is None:
                    all_protocol_rules.append(rule)

            if all_protocol_rules:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) allows ingress from 0.0.0.0/0 on all ports/protocols "
                    f"({len(all_protocol_rules)} rule(s))."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Security group {sg.name} ({sg.id}) does not allow ingress from 0.0.0.0/0 on all ports/protocols."

            findings.append(report)

        return findings
