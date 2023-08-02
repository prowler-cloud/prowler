from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.sqlserver.sqlserver_service import SQLServer

sqlserver_client = SQLServer(azure_audit_info)