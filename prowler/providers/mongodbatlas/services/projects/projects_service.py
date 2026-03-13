from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider


class Projects(MongoDBAtlasService):
    """MongoDB Atlas Projects service"""

    def __init__(self, provider: MongodbatlasProvider):
        super().__init__(__class__.__name__, provider)
        self.projects = self._list_projects()

    def _list_projects(self):
        """
        List all MongoDB Atlas projects

        Returns:
            Dict[str, Project]: Dictionary of projects indexed by project ID
        """
        logger.info("Projects - Listing MongoDB Atlas projects...")
        projects = {}

        try:
            # If project_id filter is set, only get that project
            if self.provider.project_id:
                project_data = self._make_request(
                    "GET", f"/groups/{self.provider.project_id}"
                )
                project_id = project_data["id"]

                # Get cluster count
                cluster_count = self._get_cluster_count(project_id)

                # Get network access entries
                network_access_entries = self._get_network_access_entries(project_id)

                # Get project settings
                project_settings = self._get_project_settings(project_id)

                # Get audit configuration
                audit_config = self._get_audit_config(project_id)

                projects[project_id] = Project(
                    id=project_id,
                    name=project_data.get("name", ""),
                    org_id=project_data.get("orgId", ""),
                    created=project_data.get("created", ""),
                    cluster_count=cluster_count,
                    network_access_entries=network_access_entries,
                    project_settings=project_settings,
                    audit_config=audit_config,
                )
            else:
                # Get all projects with pagination
                all_projects = self._paginate_request("/groups")

                for project_data in all_projects:
                    project_id = project_data["id"]

                    # Get cluster count
                    cluster_count = self._get_cluster_count(project_id)

                    # Get network access entries
                    network_access_entries = self._get_network_access_entries(
                        project_id
                    )

                    # Get project settings
                    project_settings = self._get_project_settings(project_id)

                    # Get audit configuration
                    audit_config = self._get_audit_config(project_id)

                    projects[project_id] = Project(
                        id=project_id,
                        name=project_data.get("name", ""),
                        org_id=project_data.get("orgId", ""),
                        created=project_data.get("created", ""),
                        cluster_count=cluster_count,
                        network_access_entries=network_access_entries,
                        project_settings=project_settings,
                        audit_config=audit_config,
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(projects)} MongoDB Atlas projects")
        return projects

    def _get_cluster_count(self, project_id: str) -> int:
        """
        Get cluster count for a project

        Args:
            project_id: Project ID

        Returns:
            int: Number of clusters in the project
        """
        try:
            clusters = self._paginate_request(f"/groups/{project_id}/clusters")
            return len(clusters)
        except Exception as error:
            logger.error(
                f"Error getting cluster count for project {project_id}: {error}"
            )
            return 0

    def _get_network_access_entries(self, project_id: str):
        """
        Get network access entries for a project

        Args:
            project_id: Project ID

        Returns:
            List[MongoDBAtlasNetworkAccessEntry]: List of network access entries
        """
        try:
            entries = self._paginate_request(f"/groups/{project_id}/accessList")
            network_entries = []
            if entries:
                for entry in entries:
                    network_entry = MongoDBAtlasNetworkAccessEntry(
                        cidr_block=entry.get("cidrBlock"),
                        ip_address=entry.get("ipAddress"),
                        aws_security_group=entry.get("awsSecurityGroup"),
                        comment=entry.get("comment"),
                        delete_after_date=entry.get("deleteAfterDate"),
                    )
                    network_entries.append(network_entry)

            return network_entries

        except Exception as error:
            logger.error(
                f"Error getting network access entries for project {project_id}: {error}"
            )
            return []

    def _get_project_settings(self, project_id: str):
        """Get project settings"""
        try:
            settings = self._make_request("GET", f"/groups/{project_id}/settings")
            project_settings = (
                ProjectSettings(
                    collect_specific_statistics=settings.get(
                        "isCollectDatabaseSpecificsStatisticsEnabled", False
                    ),
                    data_explorer=settings.get("isDataExplorerEnabled", False),
                    data_explorer_gen_ai_features=settings.get(
                        "isDataExplorerGenAIFeaturesEnabled", False
                    ),
                    data_explorer_gen_ai_sample_documents=settings.get(
                        "isDataExplorerGenAISampleDocumentPassingEnabled", False
                    ),
                    extended_storage_sizes=settings.get(
                        "isExtendedStorageSizesEnabled", False
                    ),
                    performance_advisories=settings.get(
                        "isPerformanceAdvisoriesEnabled", False
                    ),
                    real_time_performance_panel=settings.get(
                        "isRealTimePerformancePanelEnabled", False
                    ),
                    schema_advisor=settings.get("isSchemaAdvisorEnabled", False),
                )
                if settings
                else None
            )
            return project_settings
        except Exception as error:
            logger.error(
                f"Error getting project settings for project {project_id}: {error}"
            )
            return None

    def _get_audit_config(self, project_id: str):
        """Get audit configuration for a project"""
        try:
            audit_config = self._make_request("GET", f"/groups/{project_id}/auditLog")
            return (
                AuditConfig(
                    enabled=audit_config.get("enabled", False),
                    audit_filter=audit_config.get("auditFilter", None),
                )
                if audit_config
                else None
            )
        except Exception as error:
            logger.error(
                f"Error getting audit configuration for project {project_id}: {error}"
            )
            return None


class MongoDBAtlasNetworkAccessEntry(BaseModel):
    """MongoDB Atlas network access entry model"""

    cidr_block: Optional[str] = None
    ip_address: Optional[str] = None
    aws_security_group: Optional[str] = None
    comment: Optional[str] = None
    delete_after_date: Optional[str] = None


class ProjectSettings(BaseModel):
    """MongoDB Atlas Project Settings model"""

    collect_specific_statistics: bool
    data_explorer: bool
    data_explorer_gen_ai_features: bool
    data_explorer_gen_ai_sample_documents: bool
    extended_storage_sizes: bool
    performance_advisories: bool
    real_time_performance_panel: bool
    schema_advisor: bool


class AuditConfig(BaseModel):
    """MongoDB Atlas Audit Configuration model"""

    enabled: bool = False
    audit_filter: Optional[str] = None


class Project(BaseModel):
    """MongoDB Atlas Project model"""

    id: str
    name: str
    org_id: str
    created: str
    cluster_count: int
    network_access_entries: List[MongoDBAtlasNetworkAccessEntry] = []
    project_settings: Optional[ProjectSettings] = None
    audit_config: Optional[AuditConfig] = None
    location: str = "global"
