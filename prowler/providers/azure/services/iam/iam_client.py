from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.services.iam.iam_service import IAM

iam_client = IAM(azure_audit_info)
