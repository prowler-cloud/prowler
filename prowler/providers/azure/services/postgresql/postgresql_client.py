from prowler.providers.azure.services.postgresql.postgresql_service import PostgreSQL
from prowler.providers.common.provider import Provider

postgresql_client = PostgreSQL(Provider.get_global_provider())
