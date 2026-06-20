from prowler.providers.common.provider import Provider
from prowler.providers.e2e.services.database.database_service import Database

database_client = Database(Provider.get_global_provider())
