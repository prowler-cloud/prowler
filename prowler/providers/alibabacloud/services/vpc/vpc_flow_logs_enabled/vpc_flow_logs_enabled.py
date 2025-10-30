from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=vpc)
            vpc_flow_logs = [
                fl
                for fl in vpc_client.flow_logs.values()
                if fl.resource_id == vpc.vpc_id
            ]
            report.status = "FAIL"
            report.status_extended = (
                f"VPC {vpc.vpc_name} ({vpc.vpc_id}) does not have flow logs enabled."
            )
            if len(vpc_flow_logs) > 0:
                report.status = "PASS"
                report.status_extended = f"VPC {vpc.vpc_name} ({vpc.vpc_id}) has {len(vpc_flow_logs)} flow log(s) enabled."
            findings.append(report)
        return findings
