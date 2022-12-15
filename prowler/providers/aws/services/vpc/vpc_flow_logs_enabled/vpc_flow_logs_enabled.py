from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs:
            report = Check_Report_AWS(self.metadata())
            report.region = vpc.region
            if vpc.flow_log:
                report.status = "PASS"
                report.status_extended = f"VPC {vpc.id} Flow logs are enabled."
                report.resource_id = vpc.id
            else:
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.id} Flow logs are disabled."
                report.resource_id = vpc.id
            findings.append(report)

        return findings
