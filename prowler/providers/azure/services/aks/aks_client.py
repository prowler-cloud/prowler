from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.aks.aks_service import Aks

aks_client = Aks(azure_audit_info)
