from prowler.providers.azure.services.cosmosdb.cosmosdb_service import CosmosDB
from prowler.providers.common.provider import Provider

cosmosdb_client = CosmosDB(Provider.get_global_provider())
