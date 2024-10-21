from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client

class ssm_ec2_managedinstance_association_compliance_status_check(Check):
    def execute(self):
        findings = []

        # Ensure that managed instances are retrieved correctly
        for instance in ssm_client.managed_instances.values():
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn

            # Compliance check logic for EC2 managed instances
            if instance.association_compliance_status == "COMPLIANT":
                report.status = "PASS"
                report.status_extended = f"EC2 managed instance {instance.id} has a compliant association status."
            else:
                report.status = "FAIL"
                report.status_extended = f"EC2 managed instance {instance.id} does not have a compliant association status."

            findings.append(report)

        return findings
