from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client


class vpc_default_security_group_restricts_all_traffic(Check):
    """Check if the default security group restricts all traffic."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for sg in vpc_client.security_groups.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = (
                f"huaweicloud:vpc:{sg.region}:{vpc_client.audited_account}:security-group/{sg.id}"
            )

            if not sg.name:
                findings.append(report)
                continue

            has_ingress_rule_with_open_cidr = False
            has_egress_rule_with_open_cidr = False

            for rule in sg.rules:
                if rule.direction == "ingress" and rule.remote_ip_prefix in ("0.0.0.0/0", "::/0"):
                    has_ingress_rule_with_open_cidr = True
                if rule.direction == "egress" and rule.remote_ip_prefix in ("0.0.0.0/0", "::/0"):
                    has_egress_rule_with_open_cidr = True

            if has_ingress_rule_with_open_cidr or has_egress_rule_with_open_cidr:
                report.status = "FAIL"
                open_directions = []
                if has_ingress_rule_with_open_cidr:
                    open_directions.append("ingress")
                if has_egress_rule_with_open_cidr:
                    open_directions.append("egress")
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) has {' and '.join(open_directions)} rule(s) with open CIDR (0.0.0.0/0 or ::/0)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) does not have any rule with open CIDR."
                )

            findings.append(report)

        return findings
