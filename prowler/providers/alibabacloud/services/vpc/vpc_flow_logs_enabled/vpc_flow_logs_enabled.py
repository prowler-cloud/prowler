"""
Check: vpc_flow_logs_enabled

Ensures that VPC flow logs are enabled for network traffic monitoring and security analysis.
Flow logs capture information about IP traffic going to and from network interfaces in VPCs.

Risk Level: MEDIUM
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    """Check if VPC flow logs are enabled"""

    def execute(self):
        """Execute the vpc_flow_logs_enabled check"""
        findings = []

        for vpc_arn, vpc in vpc_client.vpcs.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=vpc)
            report.account_uid = vpc_client.account_id
            report.region = vpc.region
            report.resource_id = vpc.vpc_id
            report.resource_arn = vpc.arn

            # Check if this VPC has any flow logs
            vpc_flow_logs = [fl for fl in vpc_client.flow_logs.values() if fl.resource_id == vpc.vpc_id]

            if len(vpc_flow_logs) > 0:
                report.status = "PASS"
                report.status_extended = f"VPC {vpc.vpc_name} ({vpc.vpc_id}) has {len(vpc_flow_logs)} flow log(s) enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.vpc_name} ({vpc.vpc_id}) does not have flow logs enabled. Enable VPC flow logs for network traffic monitoring and security analysis."

            findings.append(report)

        return findings
