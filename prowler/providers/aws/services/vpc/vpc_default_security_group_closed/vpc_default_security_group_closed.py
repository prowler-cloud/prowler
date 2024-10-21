from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client

class vpc_default_security_group_closed(Check):
    def execute(self):
        findings = []

        # Iterate through the security groups in the VPC client
        for sg in vpc_client.security_groups:
            # Check if the security group is the default one
            if sg.is_default:
                report = Check_Report_AWS(self.metadata())
                report.region = sg.region
                report.resource_id = sg.id
                report.resource_arn = sg.arn
                report.resource_tags = sg.tags

                # Check if the default security group has any open ingress or egress rules
                if sg.ingress_rules or sg.egress_rules:
                    report.status = "FAIL"
                    report.status_extended = f"Default security group {sg.id} in VPC {sg.vpc_id} has open rules."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Default security group {sg.id} in VPC {sg.vpc_id} is closed."

                findings.append(report)

        return findings
