from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_with_outdated_ami(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"EC2 Instance {instance.id} is not using outdated AMIs."
            )

            ami = next(
                (image for image in ec2_client.images if image.id == instance.image_id),
                None,
            )
            if ami is not None and ami.deprecation_time:
                deprecation_datetime = datetime.strptime(
                    ami.deprecation_time, "%Y-%m-%dT%H:%M:%SZ"
                )
                deprecation_datetime = deprecation_datetime.replace(tzinfo=timezone.utc)
                if deprecation_datetime < datetime.now(timezone.utc):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"EC2 Instance {instance.id} is using outdated AMI {ami.id}."
                    )

            findings.append(report)

        return findings
