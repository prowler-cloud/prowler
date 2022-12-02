from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.services.storage.storage_service import Storage

storage_client = Storage(azure_audit_info)
