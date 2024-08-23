from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_no_public_ip(Check):
    def execute(self):
        findings = []
        for template in ec2_client.launch_templates:
            report = Check_Report_AWS(self.metadata())
            report.region = template.region
            report.resource_id = template.id
            report.resource_arn = template.arn

            versions_with_public_ip = []

            for version in template.versions:
                # Check if the launch template version assigns a public IP address
                if version.template_data.associate_public_ip_address:
                    versions_with_public_ip.append(str(version.version_number))

            if len(versions_with_public_ip) > 0:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 Launch Template {template.name} in template versions: "
                    f"{', '.join(versions_with_public_ip)} is configured to assign a public IP address."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"No versions of EC2 Launch Template {template.name} are configured to assign a public IP address."

            findings.append(report)

        return findings
