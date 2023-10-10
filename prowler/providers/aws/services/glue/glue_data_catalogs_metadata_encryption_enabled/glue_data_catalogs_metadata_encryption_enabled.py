from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_data_catalogs_metadata_encryption_enabled(Check):
    def execute(self):
        findings = []
        for encryption in glue_client.catalog_encryption_settings:
            # Check only if there are Glue Tables
            if encryption.tables or not glue_client.audit_info.reduce_noise:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = glue_client.audited_account
                report.resource_arn = glue_client.audited_account_arn
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
