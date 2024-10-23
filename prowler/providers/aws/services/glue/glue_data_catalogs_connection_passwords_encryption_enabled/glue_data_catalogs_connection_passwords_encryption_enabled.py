from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_data_catalogs_connection_passwords_encryption_enabled(Check):
    def execute(self):
        findings = []
        for data_catalog in glue_client.data_catalogs.values():
            # Check only if there are Glue Tables
            if data_catalog.tables or glue_client.provider.scan_unused_services:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = glue_client.audited_account
                report.resource_arn = glue_client._get_data_catalog_arn_template(
                    data_catalog.region
                )
                report.region = data_catalog.region
                report.status = "FAIL"
                report.status = "FAIL"
                report.status_extended = (
                    "Glue data catalog connection password is not encrypted."
                )
                if (
                    data_catalog.encryption_settings
                    and data_catalog.encryption_settings.password_encryption
                ):
                    report.status = "PASS"
                    report.status_extended = f"Glue data catalog connection password is encrypted with KMS key {data_catalog.encryption_settings.password_kms_id}."
                findings.append(report)
        return findings
