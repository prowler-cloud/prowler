from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.mysql.mysql_service import MySQL

sqlserver_client = MySQL(azure_audit_info)
