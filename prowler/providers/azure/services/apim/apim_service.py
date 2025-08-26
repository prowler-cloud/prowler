from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional

from azure.mgmt.apimanagement import ApiManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.services.logs.loganalytics_client import (
    loganalytics_client,
)
from prowler.providers.azure.services.logs.logsquery_client import logsquery_client
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


@dataclass
class APIMInstance:
    """APIM Instance model"""

    id: str
    name: str
    location: str
    resource_group: str
    subscription_id: str
    sku_name: str
    sku_capacity: int
    virtual_network_type: str
    publisher_email: str
    publisher_name: str
    zones: List[str]
    tags: Dict[str, str]
    log_analytics_workspace_id: Optional[str] = None


class APIM(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(ApiManagementClient, provider)
        self.instances = self._get_instances()

    def _get_workspace_customer_id(
        self, subscription: str, workspace_arm_id: str
    ) -> Optional[str]:
        """
        Get the Customer ID (GUID) for a workspace from its full ARM ID.
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
        """Retrieve the Log Analytics workspace ARM ID from an APIM instance's diagnostic settings"""
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
        """Get all APIM instances and their configured Log Analytics workspace"""
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
                            resource_group=instance.id.split("/")[4],
                            subscription_id=instance.id.split("/")[2],
                            sku_name=instance.sku.name,
                            sku_capacity=instance.sku.capacity,
                            virtual_network_type=instance.virtual_network_type,
                            publisher_email=instance.publisher_email,
                            publisher_name=instance.publisher_name,
                            zones=instance.zones or [],
                            tags=instance.tags or {},
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
    ) -> List[Dict[str, Any]]:
        """Query a specific Log Analytics workspace using its Customer ID (GUID)"""
        try:
            response = logsquery_client.clients[subscription].query_workspace(
                workspace_id=workspace_customer_id,
                query=query,
                timespan=timespan,
            )

            if response.tables:
                columns = response.tables[0].columns
                return [dict(zip(columns, row)) for row in response.tables[0].rows]

            return []

        except Exception as error:
            logger.error(
                f"Failed to query Log Analytics workspace with customer ID {workspace_customer_id}: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def get_llm_operations_logs(
        self, subscription: str, instance: APIMInstance, minutes: int = 1440
    ) -> List[Dict[str, Any]]:
        """Get LLM-related operations from the APIM instance's specific Log Analytics workspace"""
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
