from datetime import datetime, timedelta
from typing import List, Optional

from azure.mgmt.apimanagement import ApiManagementClient
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.services.logs.loganalytics_client import (
    loganalytics_client,
)
from prowler.providers.azure.services.logs.logsquery_client import logsquery_client
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class APIMInstance(BaseModel):
    """APIM Instance model"""

    id: str
    name: str
    location: str
    log_analytics_workspace_id: Optional[str] = None


class LogsQueryLogEntry(BaseModel):
    """Logs Query Log Entry model"""

    TimeGenerated: datetime
    OperationId: str
    CallerIpAddress: str
    CorrelationId: str


class APIM(AzureService):
    def __init__(self, provider: AzureProvider):
        """Initialize the APIM service client.

        Args:
            provider: The Azure provider instance containing authentication and client configuration
        """
        super().__init__(ApiManagementClient, provider)
        self.instances = self._get_instances()

    def _get_workspace_customer_id(
        self, subscription: str, workspace_arm_id: str
    ) -> Optional[str]:
        """Get the Customer ID (GUID) for a workspace from its full ARM ID.

        This method extracts the resource group and workspace name from the ARM ID
        and queries the Log Analytics client to retrieve the customer ID (GUID)
        needed for workspace-specific queries.

        Args:
            subscription: The Azure subscription ID
            workspace_arm_id: The full ARM ID of the Log Analytics workspace

        Returns:
            The customer ID (GUID) of the workspace if successful, None otherwise
        """
        try:
            resource_group = workspace_arm_id.split("/")[4]
            workspace_name = workspace_arm_id.split("/")[-1]

            workspace = loganalytics_client.clients[subscription].workspaces.get(
                resource_group_name=resource_group, workspace_name=workspace_name
            )
            return workspace.customer_id
        except Exception as error:
            logger.error(
                f"Failed to get customer ID for workspace {workspace_arm_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _get_log_analytics_workspace_id(
        self, instance_id: str, subscription: str
    ) -> Optional[str]:
        """Retrieve the Log Analytics workspace ARM ID from an APIM instance's diagnostic settings.

        This method queries the Azure Monitor diagnostic settings for a specific APIM
        instance to find the configured Log Analytics workspace. It specifically looks
        for diagnostic settings that have GatewayLogs enabled, which are essential for
        monitoring APIM API calls and operations.

        Args:
            instance_id: The ARM ID of the APIM instance
            subscription: The Azure subscription ID

        Returns:
            The ARM ID of the Log Analytics workspace if diagnostic settings are found
            and GatewayLogs are enabled, None otherwise
        """
        try:
            diagnostic_settings = monitor_client.diagnostic_settings_with_uri(
                subscription, instance_id, monitor_client.clients[subscription]
            )
            for setting in diagnostic_settings:
                if setting.workspace_id and setting.logs:
                    for log_setting in setting.logs:
                        if (
                            log_setting.enabled
                            and log_setting.category == "GatewayLogs"
                        ):
                            logger.info(
                                f"Found enabled Log Analytics workspace for APIM instance {instance_id} with category {log_setting.category}"
                            )
                            return setting.workspace_id
        except Exception as error:
            logger.error(
                f"Failed to get diagnostic settings for {instance_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return None

    def _get_instances(self):
        """Get all APIM instances and their configured Log Analytics workspace.

        This method iterates through all accessible Azure subscriptions and retrieves
        all APIM instances within each subscription. For each instance, it also
        determines the associated Log Analytics workspace by checking diagnostic
        settings. The method populates the instances dictionary with APIMInstance
        objects containing all relevant metadata and configuration.

        Returns:
            A dictionary mapping subscription IDs to lists of APIMInstance objects.
            Each APIMInstance contains the instance details and its associated
            Log Analytics workspace ID if configured.
        """
        logger.info("APIM - Getting instances...")
        instances = {}

        for subscription, client in self.clients.items():
            try:
                instances.update({subscription: []})
                apim_instances = client.api_management_service.list()

                for instance in apim_instances:
                    workspace_id = self._get_log_analytics_workspace_id(
                        instance.id, subscription
                    )
                    instances[subscription].append(
                        APIMInstance(
                            id=instance.id,
                            name=instance.name,
                            location=instance.location,
                            log_analytics_workspace_id=workspace_id,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return instances

    def query_logs(
        self,
        subscription: str,
        query: str,
        timespan: timedelta,
        workspace_customer_id: str,
    ) -> List[LogsQueryLogEntry]:
        """Query a specific Log Analytics workspace using its Customer ID (GUID).

        This method executes Kusto Query Language (KQL) queries against a specific
        Log Analytics workspace. It's used to retrieve log data for analysis and
        monitoring purposes. The method handles the response parsing and converts
        the tabular results into a list of dictionaries for easy consumption.

        Args:
            subscription: The Azure subscription ID
            query: The KQL query string to execute
            timespan: The time range for the query as a timedelta
            workspace_customer_id: The customer ID (GUID) of the Log Analytics workspace

        Returns:
            A list of dictionaries where each dictionary represents a row from the
            query results. The keys are the column names from the query response.
            Returns an empty list if the query fails or returns no results.
        """
        try:
            response = logsquery_client.clients[subscription].query_workspace(
                workspace_id=workspace_customer_id,
                query=query,
                timespan=timespan,
            )

            if response.tables:
                columns = response.tables[0].columns
                return [
                    LogsQueryLogEntry(**dict(zip(columns, row)))
                    for row in response.tables[0].rows
                ]

        except Exception as error:
            logger.error(
                f"Failed to query Log Analytics workspace with customer ID {workspace_customer_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def get_llm_operations_logs(
        self, subscription: str, instance: APIMInstance, minutes: int = 1440
    ) -> List[LogsQueryLogEntry]:
        """Get LLM-related operations from the APIM instance's specific Log Analytics workspace.

        This method retrieves logs related to Large Language Model (LLM) operations
        from a specific APIM instance. It queries the GatewayLogs table in the
        associated Log Analytics workspace to find API calls and operations that
        may be related to LLM services. The method automatically handles the
        translation from workspace ARM ID to customer ID for querying.

        Args:
            subscription: The Azure subscription ID
            instance: The APIMInstance object containing the instance details
            minutes: The time range in minutes to look back (default: 1440 = 24 hours)

        Returns:
            A list of dictionaries containing log entries with fields like
            TimeGenerated, OperationId, CallerIpAddress, and CorrelationId.
            Returns an empty list if no workspace is configured or if the query fails.
        """
        if not instance.log_analytics_workspace_id:
            logger.warning(
                f"APIM instance {instance.name} has no configured Log Analytics workspace."
            )
            return []

        # Translate the workspace ARM ID to the Customer ID (GUID) before querying
        workspace_customer_id = self._get_workspace_customer_id(
            subscription, instance.log_analytics_workspace_id
        )
        if not workspace_customer_id:
            return []

        query = f"""
        ApiManagementGatewayLogs
        | where _ResourceId has '{instance.id}'
        | project TimeGenerated, OperationId, CallerIpAddress, CorrelationId
        """
        timespan = timedelta(minutes=minutes)
        return self.query_logs(subscription, query, timespan, workspace_customer_id)
