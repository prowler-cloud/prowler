from unittest import mock

from prowler.providers.vercel.services.project.project_service import Project
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
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
