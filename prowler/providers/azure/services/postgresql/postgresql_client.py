from prowler.providers.azure.services.postgresql.postgresql_service import PostgreSQL
from prowler.providers.common.common import get_global_provider

postgresql_client = PostgreSQL(get_global_provider())
