from datetime import datetime
from typing import Optional

from alibabacloud_cs20151215 import models as cs_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class CS(AlibabaCloudService):
    """
    CS (Container Service) class for Alibaba Cloud Kubernetes (ACK).

    This class provides methods to interact with Alibaba Cloud Container Service
    to retrieve ACK clusters and their configurations.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        super().__init__(__class__.__name__, provider, global_service=False)

        # Fetch CS resources
        self.clusters = []
        self.__threading_call__(self._describe_clusters)

    def _describe_clusters(self, regional_client):
        """List all ACK clusters and fetch their details in a specific region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"CS - Describing Kubernetes clusters in {region}...")

        try:
            # DescribeClustersV1 returns cluster list
            request = cs_models.DescribeClustersV1Request()
            response = regional_client.describe_clusters_v1(request)

            if response and response.body and response.body.clusters:
                for cluster_data in response.body.clusters:
                    cluster_id = getattr(cluster_data, "cluster_id", "")

                    if not self.audit_resources or is_resource_filtered(
                        cluster_id, self.audit_resources
                    ):
                        # Get detailed information for each cluster
                        cluster_detail = self._get_cluster_detail(
                            regional_client, cluster_id
                        )

                        if cluster_detail:
                            # Extract audit project name from meta_data
                            meta_data = cluster_detail.get("meta_data", {})
                            audit_project_name = meta_data.get("AuditProjectName", "")

                            # Check RBAC status - by default RBAC is enabled on ACK clusters
                            # We check if there are any indicators that RBAC is disabled
                            rbac_enabled = self._check_rbac_enabled(
                                cluster_detail, region
                            )

                            # Get node pools to check CloudMonitor
                            cloudmonitor_enabled = self._check_cloudmonitor_enabled(
                                regional_client, cluster_id
                            )

                            # Check if cluster checks have been run in the last week
                            last_check_time = self._get_last_cluster_check(
                                regional_client, cluster_id
                            )

                            # Check addons for dashboard, network policy, etc.
                            addons_status = self._check_cluster_addons(
                                cluster_detail, region
                            )

                            # Check for public API server endpoint
                            public_access_enabled = self._check_public_access(
                                cluster_detail, region
                            )

                            self.clusters.append(
                                Cluster(
                                    id=cluster_id,
                                    name=getattr(cluster_data, "name", cluster_id),
                                    region=region,
                                    cluster_type=getattr(
                                        cluster_data, "cluster_type", ""
                                    ),
                                    state=getattr(cluster_data, "state", ""),
                                    audit_project_name=audit_project_name,
                                    log_service_enabled=bool(audit_project_name),
                                    cloudmonitor_enabled=cloudmonitor_enabled,
                                    rbac_enabled=rbac_enabled,
                                    last_check_time=last_check_time,
                                    dashboard_enabled=addons_status[
                                        "dashboard_enabled"
                                    ],
                                    network_policy_enabled=addons_status[
                                        "network_policy_enabled"
                                    ],
                                    eni_multiple_ip_enabled=addons_status[
                                        "eni_multiple_ip_enabled"
                                    ],
                                    private_cluster_enabled=not public_access_enabled,
                                )
                            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_cluster_detail(self, regional_client, cluster_id: str) -> dict:
        """Get detailed information for a specific cluster."""
        try:
            # DescribeClusterDetail returns detailed cluster information
            request = cs_models.DescribeClusterDetailRequest()
            response = regional_client.describe_cluster_detail(cluster_id, request)

            if response and response.body:
                # Convert response body to dict
                body = response.body
                result = {"meta_data": {}}

                # Check if meta_data exists in the response
                if hasattr(body, "meta_data"):
                    meta_data = body.meta_data
                    if meta_data:
                        result["meta_data"] = dict(meta_data)

                return result

            return {}

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _check_cloudmonitor_enabled(self, regional_client, cluster_id: str) -> bool:
        """Check if CloudMonitor is enabled on cluster node pools."""
        try:
            # DescribeClusterNodePools returns node pool information
            request = cs_models.DescribeClusterNodePoolsRequest()
            response = regional_client.describe_cluster_node_pools(cluster_id, request)

            if response and response.body and response.body.nodepools:
                nodepools = response.body.nodepools

                # Check if ALL node pools have CloudMonitor enabled
                # If any node pool has cms_enabled=false, the cluster fails
                for nodepool in nodepools:
                    kubernetes_config = getattr(nodepool, "kubernetes_config", None)
                    if kubernetes_config:
                        cms_enabled = getattr(kubernetes_config, "cms_enabled", False)
                        if not cms_enabled:
                            return False

                # All node pools have CloudMonitor enabled
                return True if nodepools else False

            return False

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False

    def _check_rbac_enabled(self, cluster_detail: dict, region: str) -> bool:
        """
        Check if RBAC is enabled on the cluster.

        By default, RBAC is enabled on ACK clusters and ABAC is disabled.
        We check for any indicators that RBAC might be disabled or legacy auth enabled.
        """
        try:
            # Check if cluster has RBAC enabled (default is true for ACK clusters)
            # Look for security_options or parameters that indicate RBAC status

            # Check meta_data for any RBAC-related settings
            meta_data = cluster_detail.get("meta_data", {})

            # If there's an explicit RBAC disabled flag, check it
            if "RBACEnabled" in meta_data:
                return meta_data.get("RBACEnabled", "true") in ["true", "True", True]

            # Check parameters for authorization mode
            parameters = cluster_detail.get("parameters", {})
            if parameters:
                # Check if there's an authorization mode parameter
                auth_mode = parameters.get("authorization_mode", "RBAC")
                if "ABAC" in auth_mode and "RBAC" not in auth_mode:
                    # Legacy ABAC-only mode
                    return False

            # By default, RBAC is enabled on ACK clusters
            # If we don't find explicit indicators that it's disabled, assume it's enabled
            return True

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            # Default to True as RBAC is enabled by default on ACK
            return True

    def _get_last_cluster_check(self, regional_client, cluster_id: str):
        """
        Get the most recent successful cluster check time.

        Returns the finished_at timestamp of the most recent successful cluster check,
        or None if no successful checks found.
        """
        try:
            # DescribeClusterChecks returns cluster check history
            request = cs_models.DescribeClusterChecksRequest()
            response = regional_client.describe_cluster_checks(cluster_id, request)

            if response and response.body and response.body.checks:
                checks = response.body.checks

                # Find the most recent successful check
                most_recent_check = None

                for check in checks:
                    status = getattr(check, "status", "")
                    finished_at = getattr(check, "finished_at", None)

                    if status == "Succeeded" and finished_at:
                        # Parse the timestamp
                        if most_recent_check is None or finished_at > most_recent_check:
                            most_recent_check = finished_at

                return most_recent_check

            return None

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _check_cluster_addons(self, cluster_detail: dict, region: str) -> dict:
        """
        Check cluster addons for various security configurations.

        Returns:
            dict: {
                "dashboard_enabled": bool,
                "network_policy_enabled": bool,
                "eni_multiple_ip_enabled": bool
            }
        """
        result = {
            "dashboard_enabled": False,
            "network_policy_enabled": False,
            "eni_multiple_ip_enabled": False,
        }

        try:
            meta_data = cluster_detail.get("meta_data", {})

            # Check Addons list in meta_data
            # Note: Addons structure from API is typically a string representation of JSON or a list
            # Based on sample: "Addons": [{"name": "gateway-api", ...}, ...]
            addons = meta_data.get("Addons", [])

            # If addons is string, try to parse it?
            # The SDK typically handles this conversion, but let's be safe
            if isinstance(addons, str):
                import json

                try:
                    addons = json.loads(addons)
                except Exception:
                    addons = []

            for addon in addons:
                name = addon.get("name", "")
                disabled = addon.get("disabled", False)

                # Check 7.5: Kubernetes Dashboard
                if name == "kubernetes-dashboard" and not disabled:
                    result["dashboard_enabled"] = True

                # Check 7.7 & 7.8: Terway network plugin
                if name == "terway-eniip" or name == "terway":
                    result["network_policy_enabled"] = True
                    result["eni_multiple_ip_enabled"] = True

            return result

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return result

    def _check_public_access(self, cluster_detail: dict, region: str) -> bool:
        """
        Check if cluster API server is accessible from public internet.

        Returns:
            bool: True if public access is enabled, False otherwise.
        """
        try:
            # Check master_url in cluster detail
            master_url = cluster_detail.get("master_url", "")

            # If master_url contains a public IP or DNS, public access is enabled
            # Private clusters typically don't expose a public endpoint or have specific settings

            # Check endpoint_public in parameters
            parameters = cluster_detail.get("parameters", {})
            endpoint_public = parameters.get("endpoint_public", "")

            if endpoint_public:
                return True

            # If we can't find explicit indicator, check if master_url is present
            # This is a heuristic - typical ACK public clusters expose a master_url
            if master_url:
                return True

            return False

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False


# Models for CS service
class Cluster(BaseModel):
    """ACK Cluster model."""

    id: str
    name: str
    region: str
    cluster_type: str
    state: str
    audit_project_name: str = ""
    log_service_enabled: bool = False
    cloudmonitor_enabled: bool = False
    rbac_enabled: bool = True  # Default is True for ACK clusters
    last_check_time: Optional[datetime] = None
    dashboard_enabled: bool = False
    network_policy_enabled: bool = False
    eni_multiple_ip_enabled: bool = False
    private_cluster_enabled: bool = False
