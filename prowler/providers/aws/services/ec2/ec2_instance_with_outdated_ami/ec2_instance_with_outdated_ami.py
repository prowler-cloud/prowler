from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_with_outdated_ami(Check):
    """Check if EC2 instances are using outdated AMIs.

    This check verifies whether EC2 instances are running on outdated AMIs that have
    reached their deprecation date. If an instance is using an AMI that is deprecated,
    the check fails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the outdated AMI check for EC2 instances.

        Iterates over all EC2 instances and checks if their AMIs have been deprecated.
        If an instance is using an outdated AMI, the check fails.

        Returns:
            List[Check_Report_AWS]: A list containing the results of the check for each instance.
        """
        findings = []
        for instance in ec2_client.instances:
            ami = next(
                (image for image in ec2_client.images if image.id == instance.image_id),
                None,
            )
            if ami.amazon_public:
                report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} is not using an outdated AMI."
                )

                if ami.deprecation_time:
                    deprecation_datetime = datetime.strptime(
                        ami.deprecation_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                    ).replace(tzinfo=timezone.utc)

                    if deprecation_datetime < datetime.now(timezone.utc):
                        report.status = "FAIL"
                        report.status_extended = f"EC2 Instance {instance.id} is using outdated AMI {ami.id}."

                findings.append(report)

        return findings
