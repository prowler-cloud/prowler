from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.projects.projects_service import Project
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


class TestProjectsAuditingEnabled:
    def _create_project(self, audit_config=None):
        """Helper method to create a project with audit settings"""
        if audit_config is None:
            audit_config = {}

        return Project(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            org_id=ORG_ID,
            created="2024-01-01T00:00:00Z",
            cluster_count=1,
            network_access_entries=[],
            project_settings={},
            audit_config=audit_config,
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
                "prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled.projects_client",
                new=projects_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.projects.projects_auditing_enabled.projects_auditing_enabled import (
                projects_auditing_enabled,
            )

            check = projects_auditing_enabled()
            return check.execute()

    def test_check_with_auditing_enabled(self):
        """Test check with auditing enabled"""
        project = self._create_project(audit_config={"enabled": True})
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "has database auditing enabled" in reports[0].status_extended

    def test_check_with_auditing_enabled_and_filter(self):
        """Test check with auditing enabled and filter configured"""
        project = self._create_project(
            audit_config={"enabled": True, "auditFilter": "{'action': 'authenticate'}"}
        )
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "has database auditing enabled" in reports[0].status_extended
        assert "Audit filter configured" in reports[0].status_extended

    def test_check_with_auditing_disabled(self):
        """Test check with auditing disabled"""
        project = self._create_project(audit_config={"enabled": False})
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have database auditing enabled" in reports[0].status_extended

    def test_check_with_no_audit_config(self):
        """Test check with no audit configuration"""
        project = self._create_project(audit_config={})
        reports = self._execute_check_with_project(project)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not have audit configuration available" in reports[0].status_extended
        )
