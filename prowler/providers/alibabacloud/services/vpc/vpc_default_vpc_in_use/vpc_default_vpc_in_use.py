"""
Check: vpc_default_vpc_in_use

Ensures that default VPCs are not in use for production workloads.
Default VPCs may have less secure default configurations.

Risk Level: LOW
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.vpc.vpc_client import vpc_client


class vpc_default_vpc_in_use(Check):
    def execute(self):
        findings = []
        for vpc_arn, vpc in vpc_client.vpcs.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=vpc)
            report.account_uid = vpc_client.account_id
            report.region = vpc.region
            report.resource_id = vpc.vpc_id
            report.resource_arn = vpc.arn

            if not vpc.is_default:
                report.status = "PASS"
                report.status_extended = f"VPC {vpc.vpc_name} is not a default VPC."
            else:
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.vpc_name} is a default VPC. Consider using custom VPCs for better security control."

            findings.append(report)
        return findings
