from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_data_catalogs_connection_passwords_encryption_enabled(Check):
    def execute(self):
        findings = []
        for encryption in glue_client.catalog_encryption_settings:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = glue_client.audited_account
            report.region = encryption.region
            report.status = "FAIL"
            report.status_extended = (
                "Glue data catalog connection password is not encrypted."
            )
            if encryption.password_encryption:
                report.status = "PASS"
                report.status_extended = f"Glue data catalog connection password is encrypted with KMS key {encryption.password_kms_id}."
            findings.append(report)
        return findings
