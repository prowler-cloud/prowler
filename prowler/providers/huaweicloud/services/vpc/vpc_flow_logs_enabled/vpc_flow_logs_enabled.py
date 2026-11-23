from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    """Check if VPCs have active flow logs enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        active_vpc_ids = {
            fl.resource_id
            for fl in vpc_client.flow_logs
            if fl.resource_type.lower() == "vpc"
            and fl.status.upper() == "ACTIVE"
            and fl.admin_state
        }

        for vpc in vpc_client.vpcs.values():
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=vpc)
            report.region = vpc.region
            report.resource_id = vpc.id
            report.resource_name = vpc.name
            report.resource_arn = f"huaweicloud:vpc:{vpc.region}:{vpc_client.audited_account}:vpc/{vpc.id}"

            if vpc.id in active_vpc_ids:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC {vpc.name} ({vpc.id}) has flow logs enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.name} ({vpc.id}) does not have flow logs enabled."
                )

            findings.append(report)

        return findings
