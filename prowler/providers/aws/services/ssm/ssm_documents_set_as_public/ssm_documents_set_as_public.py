from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_documents_set_as_public(Check):
    def execute(self):
        findings = []
        for document in ssm_client.documents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = document.region
            report.resource_arn = document.arn
            report.resource_id = document.name
            report.resource_tags = document.tags
            trusted_account_ids = ssm_client.audit_config.get("trusted_account_ids", [])
            if ssm_client.audited_account not in trusted_account_ids:
                trusted_account_ids.append(ssm_client.audited_account)
            if not document.account_owners or document.account_owners == [
                ssm_client.audited_account
            ]:
                report.status = "PASS"
                report.status_extended = f"SSM Document {document.name} is not public."
            elif document.account_owners == ["all"]:
                report.status = "FAIL"
                report.status_extended = f"SSM Document {document.name} is public."
            elif all(owner in trusted_account_ids for owner in document.account_owners):
                report.status = "PASS"
                report.status_extended = f"SSM Document {document.name} is shared to trusted AWS accounts: {', '.join(document.account_owners)}."
            elif not all(
                owner in trusted_account_ids for owner in document.account_owners
            ):
                report.status = "FAIL"
                report.status_extended = f"SSM Document {document.name} is shared to non-trusted AWS accounts: {', '.join(document.account_owners)}."

            findings.append(report)

        return findings
