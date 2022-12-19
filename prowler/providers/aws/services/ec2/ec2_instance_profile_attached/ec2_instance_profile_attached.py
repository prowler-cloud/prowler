from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_profile_attached(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.status = "FAIL"
            report.status_extended = f"EC2 Instance {instance.id} not associated with an Instance Profile Role."
            if instance.instance_profile:
                report.status = "PASS"
                report.status_extended = f"EC2 Instance {instance.id} associated with Instance Profile Role {instance.instance_profile['Arn']}."

            findings.append(report)

        return findings
