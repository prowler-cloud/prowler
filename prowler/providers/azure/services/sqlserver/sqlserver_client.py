from prowler.providers.azure.services.sqlserver.sqlserver_service import SQLServer
from prowler.providers.common.provider import Provider

sqlserver_client = SQLServer(Provider.get_global_provider())
