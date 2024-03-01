from prowler.providers.azure.services.cosmosdb.cosmosdb_service import CosmosDB
from prowler.providers.common.common import get_global_provider

cosmosdb_client = CosmosDB(get_global_provider())
