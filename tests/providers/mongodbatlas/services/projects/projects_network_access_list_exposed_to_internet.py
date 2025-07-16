from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.models import MongoDBAtlasNetworkAccessEntry
from prowler.providers.mongodbatlas.services.projects.projects_service import Project
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


class TestProjectsNetworkAccessListNotOpenToWorld:
    def _create_project_with_network_entries(self, network_entries):
        """Helper method to create a project with network access entries"""
        return Project(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            org_id=ORG_ID,
            created="2024-01-01T00:00:00Z",
            cluster_count=0,
            network_access_entries=network_entries,
            project_settings={},
        )

    def _execute_check_with_project(self, project):
        """Helper method to execute check with a project"""
        projects_client = MagicMock()
        projects_client.projects = {PROJECT_ID: project}

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            return check.execute()

    def test_check_with_no_network_access_entries(self):
        """Test check with no network access entries"""
        project = self._create_project_with_network_entries([])
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "has no network access list entries" in reports[0].status_extended

    def test_check_with_open_world_cidr(self):
        """Test check with open world CIDR block"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="0.0.0.0/0", comment="Open to world"
            )
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "open to the world" in reports[0].status_extended
        assert "0.0.0.0/0" in reports[0].status_extended

    def test_check_with_open_world_ipv6(self):
        """Test check with open world IPv6 CIDR block"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="::/0", comment="Open to world IPv6"
            )
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "open to the world" in reports[0].status_extended
        assert "::/0" in reports[0].status_extended

    def test_check_with_open_world_ip_address(self):
        """Test check with open world IP address"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                ip_address="0.0.0.0", comment="Open to world IP"
            )
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "open to the world" in reports[0].status_extended
        assert "0.0.0.0" in reports[0].status_extended

    def test_check_with_restricted_access(self):
        """Test check with properly restricted access"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="10.0.0.0/8", comment="Private network"
            ),
            MongoDBAtlasNetworkAccessEntry(
                ip_address="192.168.1.100", comment="Specific IP"
            ),
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "properly configured" in reports[0].status_extended
        assert "2 restricted entries" in reports[0].status_extended

    def test_check_with_mixed_access(self):
        """Test check with mixed access (both restricted and open)"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="10.0.0.0/8", comment="Private network"
            ),
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="0.0.0.0/0", comment="Open to world"
            ),
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "open to the world" in reports[0].status_extended
        assert "0.0.0.0/0" in reports[0].status_extended

    def test_check_with_aws_security_group(self):
        """Test check with AWS security group entry"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                aws_security_group="sg-12345678", comment="AWS security group"
            )
        ]
        project = self._create_project_with_network_entries(network_entries)
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "properly configured" in reports[0].status_extended
