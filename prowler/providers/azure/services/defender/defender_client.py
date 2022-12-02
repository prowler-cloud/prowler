from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.services.defender.defender_service import Defender

defender_client = Defender(azure_audit_info)
