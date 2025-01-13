from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_imdsv2_required(Check):
    def execute(self):
        findings = []
        for template in ec2_client.launch_templates:
            report = Check_Report_AWS(self.metadata(), template)

            versions_with_imdsv2_required = []
            versions_with_metadata_disabled = []
            versions_with_no_imdsv2 = []

            for version in template.versions:
                if (
                    version.template_data.http_endpoint == "enabled"
                    and version.template_data.http_tokens == "required"
                ):
                    versions_with_imdsv2_required.append(str(version.version_number))
                elif version.template_data.http_endpoint == "disabled":
                    versions_with_metadata_disabled.append(str(version.version_number))
                else:
                    versions_with_no_imdsv2.append(str(version.version_number))

            if versions_with_imdsv2_required:
                report.status = "PASS"
                report.status_extended = f"EC2 Launch Template {template.name} has IMDSv2 enabled and required in the following versions: {', '.join(versions_with_imdsv2_required)}."
            elif versions_with_metadata_disabled:
                report.status = "PASS"
                report.status_extended = f"EC2 Launch Template {template.name} has metadata service disabled in the following versions: {', '.join(versions_with_metadata_disabled)}."
            else:
                report.status = "FAIL"
                report.status_extended = f"EC2 Launch Template {template.name} has IMDSv2 disabled or not required in the following versions: {', '.join(versions_with_no_imdsv2)}."

            findings.append(report)

        return findings
