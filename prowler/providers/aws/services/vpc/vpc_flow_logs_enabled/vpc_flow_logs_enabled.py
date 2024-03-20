from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(self.metadata())
                report.region = vpc.region
                report.resource_tags = vpc.tags
                report.resource_id = vpc.id
                report.resource_arn = vpc.arn
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.name if vpc.name else vpc.id} Flow logs are disabled."
                )
                if vpc.flow_log:
                    report.status = "PASS"
                    report.status_extended = (
                        f"VPC {vpc.name if vpc.name else vpc.id} Flow logs are enabled."
                    )

                findings.append(report)

        return findings
