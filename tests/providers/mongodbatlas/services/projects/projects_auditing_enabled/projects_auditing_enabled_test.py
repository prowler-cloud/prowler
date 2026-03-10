from unittest import mock

from prowler.providers.mongodbatlas.services.projects.projects_service import (
    AuditConfig,
    Project,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


class Test_projects_auditing_enabled:
    def test_no_projects(self):
        projects_client = mock.MagicMock
        projects_client.projects = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_projects_auditing_enabled(self):
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
                audit_config=AuditConfig(
                    enabled=True,
                    audit_filter=None,
                ),
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {project_name} has database auditing enabled."
            )

    def test_projects_auditing_enabled_with_filter(self):
        projects_client = mock.MagicMock
        project_name = PROJECT_NAME
        audit_filter = '{"atype": "authenticate", "param": {"user": "admin"}}'
        projects_client.projects = {
            PROJECT_ID: Project(
                id=PROJECT_ID,
                name=project_name,
                org_id=ORG_ID,
                created="2024-01-01T00:00:00Z",
                cluster_count=1,
                network_access_entries=[],
                project_settings=None,
                audit_config=AuditConfig(
                    enabled=True,
                    audit_filter=audit_filter,
                ),
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Project {project_name} has database auditing enabled. Audit filter configured: {audit_filter}"
            )

    def test_projects_auditing_disabled(self):
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
                audit_config=AuditConfig(
                    enabled=False,
                    audit_filter=None,
                ),
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} does not have database auditing enabled."
            )

    def test_projects_no_audit_config(self):
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
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == PROJECT_ID
            assert result[0].resource_name == project_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Project {project_name} does not have audit configuration available."
            )
