from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_data_catalogs_metadata_encryption_enabled(Check):
    def execute(self):
        findings = []
        for encryption in glue_client.catalog_encryption_settings:
            # Check only if there are Glue Tables
            if encryption.tables or glue_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = glue_client.audited_account
                report.resource_arn = glue_client.__get_data_catalog_arn_template__(
                    encryption.region
                )
                report.region = encryption.region
                report.status = "FAIL"
                report.status_extended = (
                    "Glue data catalog settings have metadata encryption disabled."
                )
                if encryption.mode == "SSE-KMS":
                    report.status = "PASS"
                    report.status_extended = f"Glue data catalog settings have metadata encryption enabled with KMS key {encryption.kms_id}."
                findings.append(report)
        return findings
