from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.appinsights.appinsights_service import AppInsights

appinsights_client = AppInsights(azure_audit_info)
