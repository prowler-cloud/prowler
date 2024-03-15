from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.entra.entra_service import Entra

entra_client = Entra(azure_audit_info)
