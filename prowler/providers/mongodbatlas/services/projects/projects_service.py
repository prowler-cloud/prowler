from typing import Dict, List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService
from prowler.providers.mongodbatlas.models import MongoDBAtlasNetworkAccessEntry


class Project(BaseModel):
    """MongoDB Atlas Project model"""

    id: str
    name: str
    org_id: str
    created: str
    cluster_count: int
    network_access_entries: List[MongoDBAtlasNetworkAccessEntry] = []
    project_settings: Optional[dict] = {}


class Projects(MongoDBAtlasService):
    """MongoDB Atlas Projects service"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.projects = self._list_projects()

    def _list_projects(self) -> Dict[str, Project]:
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
                projects[project_data["id"]] = self._process_project(project_data)
            else:
                # Get all projects with pagination
                all_projects = self._paginate_request("/groups")

                for project_data in all_projects:
                    # Filter by organization if specified
                    if self.provider.organization_id:
                        if project_data.get("orgId") != self.provider.organization_id:
                            continue

                    projects[project_data["id"]] = self._process_project(project_data)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(projects)} MongoDB Atlas projects")
        return projects

    def _process_project(self, project_data: dict) -> Project:
        """
        Process a single project and fetch additional details

        Args:
            project_data: Raw project data from API

        Returns:
            Project: Processed project object
        """
        project_id = project_data["id"]

        # Get cluster count
        cluster_count = self._get_cluster_count(project_id)

        # Get network access entries
        network_access_entries = self._get_network_access_entries(project_id)

        # Get project settings
        project_settings = self._get_project_settings(project_id)

        return Project(
            id=project_id,
            name=project_data.get("name", ""),
            org_id=project_data.get("orgId", ""),
            created=project_data.get("created", ""),
            cluster_count=cluster_count,
            network_access_entries=network_access_entries,
            project_settings=project_settings,
        )

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

    def _get_network_access_entries(
        self, project_id: str
    ) -> List[MongoDBAtlasNetworkAccessEntry]:
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

    def _get_project_settings(self, project_id: str) -> dict:
        """
        Get project settings

        Args:
            project_id: Project ID

        Returns:
            dict: Project settings
        """
        try:
            settings = self._make_request("GET", f"/groups/{project_id}/settings")
            return settings
        except Exception as error:
            logger.error(
                f"Error getting project settings for project {project_id}: {error}"
            )
            return {}
