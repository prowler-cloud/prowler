from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    """Check if VPC flow logging is enabled in all VPCs."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for vpc in vpc_client.vpcs.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=vpc)
            report.region = vpc.region
            report.resource_id = vpc.id
            report.resource_arn = (
                f"acs:vpc:{vpc.region}:{vpc_client.audited_account}:vpc/{vpc.id}"
            )

            if vpc.flow_log_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC {vpc.name if vpc.name else vpc.id} has flow logs enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} does not have flow logs enabled."

            findings.append(report)

        return findings
