from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client

class ssm_document_not_public(Check):
    def execute(self):
        findings = []

        for document in ssm_client.documents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = document.region
            report.resource_id = document.name
            report.resource_arn = document.arn
            report.resource_tags = document.tags

            # Add logic to determine if the document is public
            try:
                # Call to describe the document permission to determine if it's public
                regional_client = ssm_client.regional_clients[document.region]
                document_permissions = regional_client.describe_document_permission(
                    Name=document.name, PermissionType="Share"
                )

                # Check if 'All' is in the list of account IDs (meaning it's public)
                if "All" in document_permissions.get("AccountIds", []):
                    report.status = "FAIL"
                    report.status_extended = f"SSM document {document.name} is publicly accessible."
                else:
                    report.status = "PASS"
                    report.status_extended = f"SSM document {document.name} is not publicly accessible."

            except Exception as error:
                report.status = "FAIL"
                report.status_extended = f"Error checking permissions for SSM document {document.name}: {str(error)}"

            findings.append(report)

        return findings
