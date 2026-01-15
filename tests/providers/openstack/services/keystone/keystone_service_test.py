"""Tests for OpenStack Keystone Service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.keystone.keystone_service import (
    Keystone,
    KeystoneProject,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestKeystoneService:
    """Test suite for Keystone service."""

    def test_keystone_service_initialization(self):
        """Test Keystone service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with patch.object(
            Keystone, "_list_projects", return_value=[]
        ) as mock_list_projects:
            keystone = Keystone(provider)

            assert keystone.service_name == "Keystone"
            assert keystone.provider == provider
            assert keystone.connection == provider.connection
            assert keystone.region == OPENSTACK_REGION
            assert keystone.project_id == OPENSTACK_PROJECT_ID
            assert keystone.client == provider.connection.identity
            assert keystone.projects == []
            mock_list_projects.assert_called_once()

    def test_keystone_list_projects_success(self):
        """Test successfully listing Keystone projects."""
        provider = set_mocked_openstack_provider()

        # Mock project objects from OpenStack SDK
        mock_project1 = MagicMock()
        mock_project1.id = "project-1"
        mock_project1.name = "Project One"
        mock_project1.domain_id = "default"
        mock_project1.is_enabled = True
        mock_project1.description = "First project"

        mock_project2 = MagicMock()
        mock_project2.id = "project-2"
        mock_project2.name = "Project Two"
        mock_project2.domain_id = "default"
        mock_project2.is_enabled = False
        mock_project2.description = "Second project"

        provider.connection.identity.projects.return_value = [
            mock_project1,
            mock_project2,
        ]

        keystone = Keystone(provider)

        assert len(keystone.projects) == 2

        # Check first project
        assert isinstance(keystone.projects[0], KeystoneProject)
        assert keystone.projects[0].id == "project-1"
        assert keystone.projects[0].name == "Project One"
        assert keystone.projects[0].domain_id == "default"
        assert keystone.projects[0].enabled is True
        assert keystone.projects[0].description == "First project"
        assert keystone.projects[0].region == OPENSTACK_REGION
        assert keystone.projects[0].project_id == OPENSTACK_PROJECT_ID

        # Check second project
        assert isinstance(keystone.projects[1], KeystoneProject)
        assert keystone.projects[1].id == "project-2"
        assert keystone.projects[1].name == "Project Two"
        assert keystone.projects[1].enabled is False
        assert keystone.projects[1].description == "Second project"

    def test_keystone_list_projects_empty(self):
        """Test listing projects when no projects exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.identity.projects.return_value = []

        keystone = Keystone(provider)

        assert keystone.projects == []

    def test_keystone_list_projects_with_missing_attributes(self):
        """Test listing projects when some attributes are missing."""
        provider = set_mocked_openstack_provider()

        # Mock project with missing optional attributes
        mock_project = MagicMock()
        mock_project.id = "project-1"
        # Missing name
        del mock_project.name
        # Missing domain_id
        del mock_project.domain_id
        # Missing is_enabled (should default to True via getattr)
        del mock_project.is_enabled
        # Missing description
        del mock_project.description

        provider.connection.identity.projects.return_value = [mock_project]

        keystone = Keystone(provider)

        assert len(keystone.projects) == 1
        assert keystone.projects[0].id == "project-1"
        assert keystone.projects[0].name == ""
        assert keystone.projects[0].domain_id == ""
        assert keystone.projects[0].enabled is True  # Default value from getattr
        assert keystone.projects[0].description == ""

    def test_keystone_list_projects_sdk_exception(self):
        """Test handling of SDKException when listing projects."""
        provider = set_mocked_openstack_provider()
        provider.connection.identity.projects.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        keystone = Keystone(provider)

        # Should handle exception and return empty list
        assert keystone.projects == []

    def test_keystone_list_projects_generic_exception(self):
        """Test handling of generic exception when listing projects."""
        provider = set_mocked_openstack_provider()
        provider.connection.identity.projects.side_effect = Exception(
            "Unexpected error"
        )

        keystone = Keystone(provider)

        # Should handle exception and return empty list
        assert keystone.projects == []

    def test_keystone_list_projects_iterator_exception(self):
        """Test listing projects when iterator raises exception mid-iteration."""
        provider = set_mocked_openstack_provider()

        # Mock iterator that raises exception after yielding one project
        def failing_iterator():
            mock_project1 = MagicMock()
            mock_project1.id = "project-1"
            mock_project1.name = "Project One"
            mock_project1.domain_id = "default"
            mock_project1.is_enabled = True
            mock_project1.description = "First project"
            yield mock_project1
            # Raise exception during iteration
            raise Exception("Iterator failed")

        provider.connection.identity.projects.return_value = failing_iterator()

        keystone = Keystone(provider)

        # Should handle exception gracefully - projects added before exception remain
        assert len(keystone.projects) == 1
        assert keystone.projects[0].id == "project-1"
        assert keystone.projects[0].name == "Project One"

    def test_keystone_project_dataclass_attributes(self):
        """Test KeystoneProject dataclass has all required attributes."""
        project = KeystoneProject(
            id="test-id",
            name="Test Project",
            domain_id="test-domain",
            enabled=True,
            description="Test description",
            region="RegionOne",
            project_id="parent-project",
        )

        assert project.id == "test-id"
        assert project.name == "Test Project"
        assert project.domain_id == "test-domain"
        assert project.enabled is True
        assert project.description == "Test description"
        assert project.region == "RegionOne"
        assert project.project_id == "parent-project"

    def test_keystone_service_inherits_from_base(self):
        """Test Keystone service inherits from OpenStackService."""
        provider = set_mocked_openstack_provider()

        with patch.object(Keystone, "_list_projects", return_value=[]):
            keystone = Keystone(provider)

            # Verify inherited attributes from OpenStackService
            assert hasattr(keystone, "service_name")
            assert hasattr(keystone, "provider")
            assert hasattr(keystone, "connection")
            assert hasattr(keystone, "session")
            assert hasattr(keystone, "region")
            assert hasattr(keystone, "project_id")
            assert hasattr(keystone, "identity")
            assert hasattr(keystone, "audit_config")
            assert hasattr(keystone, "fixer_config")

    def test_keystone_list_projects_with_unicode_characters(self):
        """Test listing projects with unicode characters in names/descriptions."""
        provider = set_mocked_openstack_provider()

        mock_project = MagicMock()
        mock_project.id = "project-unicode"
        mock_project.name = "Проект тест 测试项目 🚀"
        mock_project.domain_id = "default"
        mock_project.is_enabled = True
        mock_project.description = "Description with émojis 😀 and spëcial çharacters"

        provider.connection.identity.projects.return_value = [mock_project]

        keystone = Keystone(provider)

        assert len(keystone.projects) == 1
        assert keystone.projects[0].name == "Проект тест 测试项目 🚀"
        assert (
            keystone.projects[0].description
            == "Description with émojis 😀 and spëcial çharacters"
        )

    def test_keystone_list_projects_large_number(self):
        """Test listing a large number of projects."""
        provider = set_mocked_openstack_provider()

        # Create 100 mock projects
        mock_projects = []
        for i in range(100):
            mock_project = MagicMock()
            mock_project.id = f"project-{i}"
            mock_project.name = f"Project {i}"
            mock_project.domain_id = "default"
            mock_project.is_enabled = i % 2 == 0  # Alternate enabled/disabled
            mock_project.description = f"Description for project {i}"
            mock_projects.append(mock_project)

        provider.connection.identity.projects.return_value = mock_projects

        keystone = Keystone(provider)

        assert len(keystone.projects) == 100
        assert keystone.projects[0].id == "project-0"
        assert keystone.projects[99].id == "project-99"
        assert keystone.projects[0].enabled is True
        assert keystone.projects[1].enabled is False
