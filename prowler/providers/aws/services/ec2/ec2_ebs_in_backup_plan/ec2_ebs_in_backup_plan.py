from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_ebs_in_backup_plan(Check):
    def execute(self):
        findings = []

        # Iterate over each EBS volume
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags

            in_backup_plan = False

            # Check if volume ARN is in any backup plan's tags
            for backup_plan in ec2_client.backup_plans:
                if backup_plan.tags:
                    for tag_key, tag_value in backup_plan.tags.items():
                        if tag_key == 'ResourceArn' and tag_value == volume.arn:
                            in_backup_plan = True
                            break
                if in_backup_plan:
                    break

            # Set report status based on inclusion in a backup plan
            if in_backup_plan:
                report.status = "PASS"
                report.status_extended = f"EBS volume {volume.id} is included in a backup plan."
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS volume {volume.id} is not included in any backup plan."

            findings.append(report) 

        return findings
