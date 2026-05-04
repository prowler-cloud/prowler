from unittest import mock

from prowler.providers.vercel.services.project.project_service import Project
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    USER_ID,
    set_mocked_vercel_provider,
)


class TestProjectService:
    def test_list_projects_parses_security_metadata(self):
        service = Project.__new__(Project)
        service.provider = set_mocked_vercel_provider()
        service.projects = {}
        service._paginate = mock.MagicMock(
            return_value=[
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "accountId": TEAM_ID,
                    "security": {
                        "firewallEnabled": True,
                        "firewallConfigVersion": 42,
                        "managedRules": {
                            "owasp": {"active": True, "action": "log"},
                            "ai_bots": {"active": False, "action": "deny"},
                        },
                        "botIdEnabled": True,
                    },
                }
            ]
        )

        service._list_projects()

        project = service.projects[PROJECT_ID]
        assert project.firewall_enabled is True
        assert project.firewall_config_version == "42"
        assert project.managed_rules == {
            "owasp": {"active": True, "action": "log"},
            "ai_bots": {"active": False, "action": "deny"},
        }
        assert project.bot_id_enabled is True

    def test_list_projects_uses_scoped_team_billing_plan(self):
        service = Project.__new__(Project)
        service.provider = set_mocked_vercel_provider(
            billing_plan="enterprise",
            team_billing_plan="hobby",
        )
        service.projects = {}
        service._paginate = mock.MagicMock(
            return_value=[
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "accountId": TEAM_ID,
                }
            ]
        )

        service._list_projects()

        project = service.projects[PROJECT_ID]
        assert project.billing_plan == "hobby"

    def test_list_projects_uses_user_billing_plan_for_user_scoped_project(self):
        service = Project.__new__(Project)
        service.provider = set_mocked_vercel_provider(
            billing_plan="enterprise",
            team_billing_plan="hobby",
        )
        service.projects = {}
        service._paginate = mock.MagicMock(
            return_value=[
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "accountId": USER_ID,
                }
            ]
        )

        service._list_projects()

        project = service.projects[PROJECT_ID]
        assert project.billing_plan == "enterprise"

    def test_list_projects_does_not_guess_billing_plan_without_scope(self):
        service = Project.__new__(Project)
        service.provider = set_mocked_vercel_provider(
            billing_plan="enterprise",
            team_billing_plan="hobby",
        )
        service.provider.session.team_id = None
        service.projects = {}
        service._paginate = mock.MagicMock(
            return_value=[
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                }
            ]
        )

        service._list_projects()

        project = service.projects[PROJECT_ID]
        assert project.billing_plan is None
