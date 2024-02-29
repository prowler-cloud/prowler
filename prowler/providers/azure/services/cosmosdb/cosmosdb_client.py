from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.services.cosmosdb.cosmosdb_service import CosmosDB

cosmosdb_client = CosmosDB(azure_audit_info)
