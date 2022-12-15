from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_imdsv2_enabled(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.status = "FAIL"
            report.status_extended = (
                f"EC2 Instance {instance.id} has IMDSv2 disabled or not required."
            )
            if (
                instance.http_endpoint == "enabled"
                and instance.http_tokens == "required"
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} has IMDSv2 enabled and required."
                )

            findings.append(report)

        return findings
