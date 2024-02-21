from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.network.network_service import Network

network_client = Network(azure_audit_info)
