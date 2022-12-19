from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client


class ssm_documents_set_as_public(Check):
    def execute(self):
        findings = []
        for document in ssm_client.documents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = document.region
            report.resource_arn = f"arn:aws:ssm:{document.region}:{ssm_client.audited_account}:document/{document.name}"
            report.resource_id = document.name

            if document.account_owners:
                report.status = "FAIL"
                report.status_extended = f"SSM Document {document.name} is public"
            else:
                report.status = "PASS"
                report.status_extended = f"SSM Document {document.name} is not public"

            findings.append(report)

        return findings
