from unittest import mock

from prowler.providers.mongodbatlas.services.projects.projects_service import (
    MongoDBAtlasNetworkAccessEntry,
    Project,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


class Test_projects_network_access_list_exposed_to_internet:
    def test_no_projects(self):
        projects_client = mock.MagicMock
        projects_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 0

    def test_projects_no_network_access_entries(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} has no network access list entries configured, which may allow unrestricted access."
            )

    def test_projects_open_world_cidr_ipv4(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[
                    MongoDBAtlasNetworkAccessEntry(
                        cidr_block="0.0.0.0/0",
                        comment="Open to world",
                    )
                ],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} has network access entries open to the world: CIDR: 0.0.0.0/0. This allows unrestricted access from anywhere on the internet."
            )

    def test_projects_open_world_cidr_ipv6(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[
                    MongoDBAtlasNetworkAccessEntry(
                        cidr_block="::/0",
                        comment="Open to world IPv6",
                    )
                ],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} has network access entries open to the world: CIDR: ::/0. This allows unrestricted access from anywhere on the internet."
            )

    def test_projects_open_world_ip_address(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[
                    MongoDBAtlasNetworkAccessEntry(
                        ip_address="0.0.0.0",
                        comment="Open to world IP",
                    )
                ],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} has network access entries open to the world: IP: 0.0.0.0. This allows unrestricted access from anywhere on the internet."
            )

    def test_projects_restricted_access(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[
                    MongoDBAtlasNetworkAccessEntry(
                        cidr_block="10.0.0.0/8",
                        comment="Private network",
                    ),
                    MongoDBAtlasNetworkAccessEntry(
                        ip_address="192.168.1.100",
                        comment="Specific IP",
                    ),
                ],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {project_name} has properly configured network access list with 2 restricted entries."
            )

    def test_projects_mixed_access(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[
                    MongoDBAtlasNetworkAccessEntry(
                        cidr_block="10.0.0.0/8",
                        comment="Private network",
                    ),
                    MongoDBAtlasNetworkAccessEntry(
                        cidr_block="0.0.0.0/0",
                        comment="Open to world",
                    ),
                ],
                project_settings=None,
                audit_config=None,
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_network_access_list_exposed_to_internet.projects_network_access_list_exposed_to_internet import (
                projects_network_access_list_exposed_to_internet,
            )

            check = projects_network_access_list_exposed_to_internet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} has network access entries open to the world: CIDR: 0.0.0.0/0. This allows unrestricted access from anywhere on the internet."
            )
