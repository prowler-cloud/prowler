from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.services.aad.aad_service import AAD

aad_client = AAD(azure_audit_info)
