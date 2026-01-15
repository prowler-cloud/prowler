"""Tests for keystone_projects_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.keystone.keystone_service import (
    KeystoneProject,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_keystone_projects_enabled:
    """Test suite for keystone_projects_enabled check."""

    def test_no_projects(self):
        """Test when no projects exist."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_project_enabled(self):
        """Test when a project is enabled (PASS)."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-1",
                name="Test Project",
                domain_id="default",
                enabled=True,
                description="Test project description",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Project Test Project is enabled."
            assert result[0].resource_name == "Test Project"
            assert result[0].resource_id == "project-1"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_project_disabled(self):
        """Test when a project is disabled (FAIL)."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-2",
                name="Disabled Project",
                domain_id="default",
                enabled=False,
                description="Disabled project",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Project Disabled Project is disabled."
            assert result[0].resource_name == "Disabled Project"
            assert result[0].resource_id == "project-2"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_projects_mixed(self):
        """Test with multiple projects in mixed states."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-enabled-1",
                name="Enabled Project 1",
                domain_id="default",
                enabled=True,
                description="First enabled project",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            ),
            KeystoneProject(
                id="project-disabled-1",
                name="Disabled Project 1",
                domain_id="default",
                enabled=False,
                description="First disabled project",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            ),
            KeystoneProject(
                id="project-enabled-2",
                name="Enabled Project 2",
                domain_id="default",
                enabled=True,
                description="Second enabled project",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            ),
            KeystoneProject(
                id="project-disabled-2",
                name="Disabled Project 2",
                domain_id="default",
                enabled=False,
                description="Second disabled project",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 4

            # Check enabled projects (PASS)
            enabled_results = [r for r in result if r.status == "PASS"]
            assert len(enabled_results) == 2
            assert all("is enabled" in r.status_extended for r in enabled_results)

            # Check disabled projects (FAIL)
            disabled_results = [r for r in result if r.status == "FAIL"]
            assert len(disabled_results) == 2
            assert all("is disabled" in r.status_extended for r in disabled_results)

    def test_project_without_name_uses_id(self):
        """Test when project has no name, uses ID in status message."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-no-name",
                name="",  # Empty name
                domain_id="default",
                enabled=True,
                description="Project without name",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            # Should use ID when name is empty
            assert result[0].status_extended == "Project project-no-name is enabled."
            assert result[0].resource_id == "project-no-name"

    def test_project_with_none_name_uses_id(self):
        """Test when project name is None, uses ID in status message."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-none-name",
                name=None,  # None name
                domain_id="default",
                enabled=False,
                description="Project with None name",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Should use ID when name is None
            assert result[0].status_extended == "Project project-none-name is disabled."
            assert result[0].resource_id == "project-none-name"

    def test_all_projects_enabled(self):
        """Test when all projects are enabled."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id=f"project-{i}",
                name=f"Project {i}",
                domain_id="default",
                enabled=True,
                description=f"Project {i} description",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
            for i in range(5)
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 5
            assert all(r.status == "PASS" for r in result)
            assert all("is enabled" in r.status_extended for r in result)

    def test_all_projects_disabled(self):
        """Test when all projects are disabled."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id=f"project-{i}",
                name=f"Project {i}",
                domain_id="default",
                enabled=False,
                description=f"Project {i} description",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
            for i in range(3)
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 3
            assert all(r.status == "FAIL" for r in result)
            assert all("is disabled" in r.status_extended for r in result)

    def test_project_with_unicode_name(self):
        """Test project with unicode characters in name."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-unicode",
                name="プロジェクト 测试 🚀",
                domain_id="default",
                enabled=True,
                description="Unicode test",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "プロジェクト 测试 🚀" in result[0].status_extended
            assert result[0].resource_name == "プロジェクト 测试 🚀"

    def test_check_metadata(self):
        """Test that check metadata is correctly set."""
        keystone_client = mock.MagicMock()
        keystone_client.projects = [
            KeystoneProject(
                id="project-1",
                name="Test Project",
                domain_id="default",
                enabled=True,
                description="Test",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled.keystone_client",  # noqa: E501
                new=keystone_client,
            ),
        ):
            from prowler.providers.openstack.services.keystone.keystone_projects_enabled.keystone_projects_enabled import (  # noqa: E501
                keystone_projects_enabled,
            )

            check = keystone_projects_enabled()
            result = check.execute()

            assert len(result) == 1
            # Check that metadata fields are present
            assert result[0].check_metadata.CheckID == "keystone_projects_enabled"
            assert result[0].check_metadata.ServiceName == "keystone"
            assert result[0].check_metadata.CheckTitle == "Keystone project is enabled"
            assert result[0].check_metadata.Severity == "medium"
