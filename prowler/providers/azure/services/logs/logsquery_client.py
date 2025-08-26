from prowler.providers.azure.services.logs.logs_service import LogsQuery
from prowler.providers.common.provider import Provider

logsquery_client = LogsQuery(Provider.get_global_provider())
