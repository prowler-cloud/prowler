from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.vpc.vpc_client import vpc_client


class vpc_default_vpc_in_use(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=vpc)
            report.status = "FAIL"
            report.status_extended = f"VPC {vpc.vpc_name} is a default VPC."
            if not vpc.is_default:
                report.status = "PASS"
                report.status_extended = f"VPC {vpc.vpc_name} is not a default VPC."
            findings.append(report)
        return findings
