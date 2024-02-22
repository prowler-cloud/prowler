from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.app.app_service import App

app_client = App(azure_audit_info)
