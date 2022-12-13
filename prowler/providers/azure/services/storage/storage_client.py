from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.storage.storage_service import Storage

storage_client = Storage(azure_audit_info)
