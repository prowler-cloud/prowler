from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.keyvault.keyvault_service import KeyVault

keyvault_client = KeyVault(azure_audit_info)
