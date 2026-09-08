from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client


class vpc_security_group_open_egress(Check):
    """Check if VPC security groups allow unrestricted egress to the internet."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Execute the unrestricted egress check.

        Returns:
            list[CheckReportHuaweiCloud]: Reports for the evaluated security groups.
        """
        findings = []

        for sg in vpc_client.security_groups.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = (
                f"huaweicloud:vpc:{sg.region}:"
                f"{vpc_client.audited_account}:security-group/{sg.id}"
            )

            open_egress_destination = None
            for rule in sg.rules:
                if (
                    rule.direction != "egress"
                    or rule.action != "allow"
                    or rule.remote_group_id
                    or rule.remote_address_group_id
                ):
                    continue
                if rule.remote_ip_prefix in ("0.0.0.0/0", "::/0"):
                    open_egress_destination = rule.remote_ip_prefix
                    break
                if not rule.remote_ip_prefix:
                    open_egress_destination = "all destinations"
                    break

            if open_egress_destination:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) allows open egress "
                    f"({open_egress_destination}) to the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {sg.name} ({sg.id}) does not allow open egress "
                    f"to the internet."
                )

            findings.append(report)

        return findings
