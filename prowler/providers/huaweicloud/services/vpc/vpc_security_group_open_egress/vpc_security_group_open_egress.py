from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client


class vpc_security_group_open_egress(Check):
    """Check if VPC security groups allow open egress (0.0.0.0/0) to the internet."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for sg in vpc_client.security_groups.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = (
                f"huaweicloud:vpc:{sg.region}:"
                f"{vpc_client.audited_account}:security-group/{sg.id}"
            )

            has_open_egress = False
            for rule in sg.rules:
                if rule.direction != "egress":
                    continue
                if rule.remote_ip_prefix in ("0.0.0.0/0", "::/0"):
                    has_open_egress = True
                    break

            if has_open_egress:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) allows open egress (0.0.0.0/0) "
                    f"to the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) does not allow open egress "
                    f"to the internet."
                )

            findings.append(report)

        return findings
