from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_flow_logs_enabled(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.name if vpc.name else vpc.id} Flow logs are disabled."
                )
                if vpc.flow_log:
                    if vpc.flow_log_delivery_success is True:
                        report.status = "PASS"
                        report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} Flow logs are enabled."
                    elif vpc.flow_log_delivery_success is False:
                        report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} Flow log delivery has failed for all configured flow logs."
                    else:
                        report.status = "MANUAL"
                        report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} Flow logs are configured but successful delivery could not be verified."

                findings.append(report)

        return findings
