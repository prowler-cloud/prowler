from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.postgresql.postgresql_service import PostgreSQL

postgresql_client = PostgreSQL(azure_audit_info)
