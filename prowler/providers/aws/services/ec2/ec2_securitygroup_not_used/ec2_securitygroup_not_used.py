from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_not_used(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            # Default security groups can not be deleted, so ignore them
            if security_group.name != "default":
                report = Check_Report_AWS(self.metadata())
                report.region = security_group.region
                report.resource_details = security_group.name
                report.resource_id = security_group.id
                report.resource_arn = security_group.arn
                report.resource_tags = security_group.tags
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) it is being used."
                sg_in_lambda = False
                sg_associated = False
                for function in awslambda_client.functions.values():
                    if security_group.id in function.security_groups:
                        sg_in_lambda = True
                for sg in ec2_client.security_groups:
                    if security_group.id in sg.associated_sgs:
                        sg_associated = True
                if (
                    len(security_group.network_interfaces) == 0
                    and not sg_in_lambda
                    and not sg_associated
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) it is not being used."

                findings.append(report)

        return findings
