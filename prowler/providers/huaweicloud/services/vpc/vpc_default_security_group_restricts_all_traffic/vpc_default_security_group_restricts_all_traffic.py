from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client
from prowler.providers.huaweicloud.services.vpc.vpc_service import (
    DEFAULT_SECURITY_GROUP_NAMES,
    rule_source_is_open,
)


class vpc_default_security_group_restricts_all_traffic(Check):
    """Check if the default security group restricts all traffic."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for sg in vpc_client.security_groups.values():
            if sg.name not in DEFAULT_SECURITY_GROUP_NAMES:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=sg)
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = f"huaweicloud:vpc:{sg.region}:{vpc_client.audited_account}:security-group/{sg.id}"

            open_directions = []
            for rule in sg.rules:
                if rule.direction not in ("ingress", "egress"):
                    continue
                if not rule_source_is_open(rule):
                    continue
                if rule.direction not in open_directions:
                    open_directions.append(rule.direction)

            if open_directions:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default security group {sg.name} ({sg.id}) has "
                    f"{' and '.join(open_directions)} rule(s) open to any source."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Default security group {sg.name} ({sg.id}) does not "
                    "have any rule open to any source."
                )

            findings.append(report)

        return findings
