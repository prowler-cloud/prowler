from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.iam.iam_service import IAM

iam_client = IAM(azure_audit_info)
