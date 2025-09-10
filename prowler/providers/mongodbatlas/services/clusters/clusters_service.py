from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class Clusters(MongoDBAtlasService):
    """MongoDB Atlas Clusters service"""

    def __init__(self, provider: MongodbatlasProvider):
        super().__init__(__class__.__name__, provider)
        self.clusters = self._list_clusters()

    def _list_clusters(self):
        """
        List all MongoDB Atlas clusters across all projects

        Returns:
            Dict[str, Cluster]: Dictionary of clusters indexed by cluster name
        """
        logger.info("Clusters - Listing MongoDB Atlas clusters...")
        clusters = {}

        try:
            for project in projects_client.projects.values():
                logger.info(f"Getting clusters for project {project.name}...")
                try:
                    project_clusters = {}
                    clusters_data = self._paginate_request(
                        f"/groups/{project.id}/clusters"
                    )
                    for cluster_data in clusters_data:
                        # Process cluster data
                        cluster_name = cluster_data.get("name", "")

                        # Get encryption provider
                        encryption_provider = None
                        encryption_at_rest = cluster_data.get(
                            "encryptionAtRestProvider"
                        )
                        if encryption_at_rest:
                            encryption_provider = encryption_at_rest
                        else:
                            provider_settings = cluster_data.get("providerSettings", {})
                            encrypt_ebs_volume = provider_settings.get(
                                "encryptEBSVolume", False
                            )
                            if encrypt_ebs_volume:
                                encryption_provider = provider_settings.get(
                                    "providerName", "AWS"
                                )

                        # Get backup status
                        backup_enabled = cluster_data.get("backupEnabled", False)
                        pit_enabled = cluster_data.get("pitEnabled", False)
                        backup_enabled = backup_enabled or pit_enabled

                        # Create cluster object
                        cluster = Cluster(
                            id=cluster_data.get("id", ""),
                            name=cluster_name,
                            project_id=project.id,
                            project_name=project.name,
                            mongo_db_version=cluster_data.get("mongoDBVersion", ""),
                            cluster_type=cluster_data.get("clusterType", ""),
                            state_name=cluster_data.get("stateName", ""),
                            encryption_at_rest_provider=encryption_provider,
                            backup_enabled=backup_enabled,
                            auth_enabled=cluster_data.get("authEnabled", False),
                            ssl_enabled=cluster_data.get("sslEnabled", False),
                            provider_settings=cluster_data.get("providerSettings", {}),
                            replication_specs=cluster_data.get("replicationSpecs", []),
                            disk_size_gb=cluster_data.get("diskSizeGB"),
                            num_shards=cluster_data.get("numShards"),
                            replication_factor=cluster_data.get("replicationFactor"),
                            auto_scaling=cluster_data.get("autoScaling", {}),
                            mongo_db_major_version=cluster_data.get(
                                "mongoDBMajorVersion"
                            ),
                            paused=cluster_data.get("paused", False),
                            pit_enabled=pit_enabled,
                            connection_strings=cluster_data.get(
                                "connectionStrings", {}
                            ),
                            tags=cluster_data.get("tags", []),
                            location=cluster_data.get("replicationSpecs", {})[0]
                            .get("regionConfigs", {})[0]
                            .get("regionName", ""),
                        )

                        # Use a unique key combining project_id and cluster_name
                        cluster_key = f"{project.id}:{cluster.name}"
                        project_clusters[cluster_key] = cluster
                    clusters.update(project_clusters)
                except Exception as error:
                    logger.error(
                        f"Error getting clusters for project {project.name}: {error}"
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(clusters)} MongoDB Atlas clusters")
        return clusters


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
    auth_enabled: bool = False
    ssl_enabled: bool = False
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
    location: Optional[str] = None
