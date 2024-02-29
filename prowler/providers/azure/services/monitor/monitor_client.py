from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.monitor.monitor_service import Monitor

monitor_client = Monitor(azure_audit_info)
