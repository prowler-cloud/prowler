from typing import Dict, List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService


class Cluster(BaseModel):
    """MongoDB Atlas Cluster model"""

    id: str
    name: str
    project_id: str
    project_name: str
    mongo_db_version: str
    cluster_type: str
    state_name: str
    encryption_at_rest_provider: Optional[str] = None
    backup_enabled: bool = False
    provider_settings: Optional[dict] = {}
    replication_specs: Optional[List[dict]] = []
    disk_size_gb: Optional[float] = None
    num_shards: Optional[int] = None
    replication_factor: Optional[int] = None
    auto_scaling: Optional[dict] = {}
    mongo_db_major_version: Optional[str] = None
    paused: bool = False
    pit_enabled: bool = False
    connection_strings: Optional[dict] = {}
    tags: Optional[List[dict]] = []


class Clusters(MongoDBAtlasService):
    """MongoDB Atlas Clusters service"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.clusters = self._list_clusters()

    def _list_clusters(self) -> Dict[str, Cluster]:
        """
        List all MongoDB Atlas clusters across all projects

        Returns:
            Dict[str, Cluster]: Dictionary of clusters indexed by cluster name
        """
        logger.info("Clusters - Listing MongoDB Atlas clusters...")
        clusters = {}

        try:
            from prowler.providers.mongodbatlas.services.projects.projects_client import (
                projects_client,
            )

            for project in projects_client.projects.values():
                project_clusters = self._get_project_clusters(project.id, project.name)
                clusters.update(project_clusters)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(clusters)} MongoDB Atlas clusters")
        return clusters

    def _get_project_clusters(
        self, project_id: str, project_name: str
    ) -> Dict[str, Cluster]:
        """
        Get all clusters for a specific project

        Args:
            project_id: Project ID
            project_name: Project name

        Returns:
            Dict[str, Cluster]: Dictionary of clusters in the project
        """
        project_clusters = {}

        try:
            clusters_data = self._paginate_request(f"/groups/{project_id}/clusters")

            for cluster_data in clusters_data:
                cluster = self._process_cluster(cluster_data, project_id, project_name)
                # Use a unique key combining project_id and cluster_name
                cluster_key = f"{project_id}:{cluster.name}"
                project_clusters[cluster_key] = cluster

        except Exception as error:
            logger.error(f"Error getting clusters for project {project_id}: {error}")

        return project_clusters

    def _process_cluster(
        self, cluster_data: dict, project_id: str, project_name: str
    ) -> Cluster:
        """
        Process a single cluster and fetch additional details

        Args:
            cluster_data: Raw cluster data from API
            project_id: Project ID
            project_name: Project name

        Returns:
            Cluster: Processed cluster object
        """
        cluster_name = cluster_data.get("name", "")

        encryption_provider = self._get_encryption_at_rest_provider(cluster_data)

        backup_enabled = self._get_backup_enabled(cluster_data)

        provider_settings = cluster_data.get("providerSettings", {})

        replication_specs = cluster_data.get("replicationSpecs", [])

        auto_scaling = cluster_data.get("autoScaling", {})

        connection_strings = cluster_data.get("connectionStrings", {})

        tags = cluster_data.get("tags", [])

        return Cluster(
            id=cluster_data.get("id", ""),
            name=cluster_name,
            project_id=project_id,
            project_name=project_name,
            mongo_db_version=cluster_data.get("mongoDBVersion", ""),
            cluster_type=cluster_data.get("clusterType", ""),
            state_name=cluster_data.get("stateName", ""),
            encryption_at_rest_provider=encryption_provider,
            backup_enabled=backup_enabled,
            provider_settings=provider_settings,
            replication_specs=replication_specs,
            disk_size_gb=cluster_data.get("diskSizeGB"),
            num_shards=cluster_data.get("numShards"),
            replication_factor=cluster_data.get("replicationFactor"),
            auto_scaling=auto_scaling,
            mongo_db_major_version=cluster_data.get("mongoDBMajorVersion"),
            paused=cluster_data.get("paused", False),
            pit_enabled=cluster_data.get("pitEnabled", False),
            connection_strings=connection_strings,
            tags=tags,
        )

    def _get_encryption_at_rest_provider(self, cluster_data: dict) -> Optional[str]:
        """
        Get encryption at rest provider from cluster data

        Args:
            cluster_data: Cluster data from API

        Returns:
            Optional[str]: Encryption provider or None
        """
        try:
            encryption_at_rest = cluster_data.get("encryptionAtRestProvider")

            if encryption_at_rest:
                return encryption_at_rest

            provider_settings = cluster_data.get("providerSettings", {})
            encrypt_ebs_volume = provider_settings.get("encryptEBSVolume", False)

            if encrypt_ebs_volume:
                return provider_settings.get("providerName", "AWS")

            return None

        except Exception as error:
            logger.error(f"Error getting encryption provider for cluster: {error}")
            return None

    def _get_backup_enabled(self, cluster_data: dict) -> bool:
        """
        Get backup enabled status from cluster data

        Args:
            cluster_data: Cluster data from API

        Returns:
            bool: True if backup is enabled, False otherwise
        """
        try:
            backup_enabled = cluster_data.get("backupEnabled", False)

            # Also check for point-in-time enabled as an indicator of backup
            pit_enabled = cluster_data.get("pitEnabled", False)

            return backup_enabled or pit_enabled

        except Exception as error:
            logger.error(f"Error getting backup status for cluster: {error}")
            return False
