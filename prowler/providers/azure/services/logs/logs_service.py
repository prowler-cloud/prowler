from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.monitor.query import LogsQueryClient

from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class LogsQuery(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(LogsQueryClient, provider)


class LogAnalytics(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(LogAnalyticsManagementClient, provider)
