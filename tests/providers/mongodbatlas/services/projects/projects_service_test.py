from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.models import MongoDBAtlasSession
from prowler.providers.mongodbatlas.services.projects.projects_service import Projects
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ATLAS_PRIVATE_KEY,
    ATLAS_PUBLIC_KEY,
    MOCK_NETWORK_ACCESS_RESPONSE,
    MOCK_PROJECT_RESPONSE,
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
)


class TestProjectsService:
    def test_projects_service_initialization(self):
        """Test Projects service initialization"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )
        mock_provider.project_id = None
        mock_provider.organization_id = None

        with patch.object(Projects, "_list_projects", return_value={}):
            service = Projects(mock_provider)

            assert service.service_name == "Projects"
            assert service.provider == mock_provider
            assert service.projects == {}

    def test_list_projects_all(self):
        """Test listing all projects"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )
        mock_provider.project_id = None
        mock_provider.organization_id = None

        with (
            patch.object(
                Projects, "_paginate_request", return_value=[MOCK_PROJECT_RESPONSE]
            ),
            patch.object(Projects, "_process_project") as mock_process,
        ):
            mock_process.return_value = MagicMock()
            mock_process.return_value.id = PROJECT_ID
            mock_process.return_value.name = PROJECT_NAME

            service = Projects(mock_provider)

            assert len(service.projects) == 1
            assert PROJECT_ID in service.projects

    def test_list_projects_with_project_filter(self):
        """Test listing projects with project ID filter"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )
        mock_provider.project_id = PROJECT_ID
        mock_provider.organization_id = None

        with (
            patch.object(Projects, "_make_request", return_value=MOCK_PROJECT_RESPONSE),
            patch.object(Projects, "_process_project") as mock_process,
        ):
            mock_process.return_value = MagicMock()
            mock_process.return_value.id = PROJECT_ID

            service = Projects(mock_provider)

            assert len(service.projects) == 1

    def test_list_projects_with_organization_filter(self):
        """Test listing projects with organization ID filter"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )
        mock_provider.project_id = None
        mock_provider.organization_id = ORG_ID

        with (
            patch.object(
                Projects, "_paginate_request", return_value=[MOCK_PROJECT_RESPONSE]
            ),
            patch.object(Projects, "_process_project") as mock_process,
        ):
            mock_process.return_value = MagicMock()
            mock_process.return_value.id = PROJECT_ID

            service = Projects(mock_provider)

            assert len(service.projects) == 1

    def test_get_network_access_entries(self):
        """Test getting network access entries"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        service = Projects(mock_provider)

        with patch.object(
            service,
            "_paginate_request",
            return_value=MOCK_NETWORK_ACCESS_RESPONSE["results"],
        ):
            entries = service._get_network_access_entries(PROJECT_ID)

            assert len(entries) == 2
            assert entries[0].cidr_block == "0.0.0.0/0"
            assert entries[1].cidr_block == "10.0.0.0/8"

    def test_get_cluster_count(self):
        """Test getting cluster count"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        service = Projects(mock_provider)

        with patch.object(
            service, "_paginate_request", return_value=["cluster1", "cluster2"]
        ):
            count = service._get_cluster_count(PROJECT_ID)

            assert count == 2

    def test_get_project_settings(self):
        """Test getting project settings"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        service = Projects(mock_provider)

        mock_settings = {"isCollectDatabaseSpecificsStatisticsEnabled": True}

        with patch.object(service, "_make_request", return_value=mock_settings):
            settings = service._get_project_settings(PROJECT_ID)

            assert settings == mock_settings

    def test_process_project(self):
        """Test processing a single project"""
        mock_provider = MagicMock()
        mock_provider.session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        service = Projects(mock_provider)

        with (
            patch.object(service, "_get_cluster_count", return_value=2),
            patch.object(service, "_get_network_access_entries", return_value=[]),
            patch.object(service, "_get_project_settings", return_value={}),
        ):
            project = service._process_project(MOCK_PROJECT_RESPONSE)

            assert project.id == PROJECT_ID
            assert project.name == PROJECT_NAME
            assert project.org_id == ORG_ID
            assert project.cluster_count == 2
