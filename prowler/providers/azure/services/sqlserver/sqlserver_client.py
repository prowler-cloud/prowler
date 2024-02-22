from prowler.providers.azure.services.sqlserver.sqlserver_service import SQLServer
from prowler.providers.common.common import get_global_provider

sqlserver_client = SQLServer(get_global_provider())
