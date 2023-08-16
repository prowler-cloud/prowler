from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_detailed_monitoring_enabled(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = f"EC2 Instance {instance.id} has detailed monitoring enabled."
            if instance.monitoring_state != "enabled":
               report.status = "FAIL"
               report.status_extended = f"EC2 Instance {instance.id} does not have detailed monitoring enabled."

            findings.append(report)

        return findings
