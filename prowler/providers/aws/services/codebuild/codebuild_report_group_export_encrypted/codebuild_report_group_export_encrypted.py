from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_report_group_export_encrypted(Check):
    def execute(self):
        findings = []
        for report_group in codebuild_client.report_groups.values():
            if report_group.export_config and report_group.export_config.type == "S3":
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=report_group
                )
                report.status = "PASS"
                report.status_extended = f"CodeBuild report group {report_group.name} exports are encrypted at {report_group.export_config.bucket_location} with KMS key {report_group.export_config.encryption_key}."

                if not report_group.export_config.encrypted:
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild report group {report_group.name} exports are not encrypted at {report_group.export_config.bucket_location}."

                findings.append(report)

        return findings
