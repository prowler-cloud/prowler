from unittest import mock

from prowler.providers.vercel.services.project.project_service import VercelProject
from prowler.providers.vercel.services.security.security_service import Security
from tests.providers.vercel.vercel_fixtures import PROJECT_ID, PROJECT_NAME, TEAM_ID


class TestSecurityService:
    def test_fetch_firewall_config_reads_active_version_and_normalizes_response(self):
        project = VercelProject(id=PROJECT_ID, name=PROJECT_NAME, team_id=TEAM_ID)
        service = Security.__new__(Security)
        service.firewall_configs = {}

        service._get = mock.MagicMock(
            return_value={
                "active": {
                    "firewallEnabled": True,
                    "managedRules": {
                        "owasp": {"active": True, "action": "deny"},
                        "ai_bots": {"active": False, "action": "deny"},
                    },
                    "rules": [
                        {
                            "id": "rule-custom",
                            "name": "Block admin access",
                            "active": True,
                            "conditionGroup": [
                                {
                                    "conditions": [
                                        {
                                            "type": "path",
                                            "op": "pre",
                                            "value": "/admin",
                                        }
                                    ]
                                }
                            ],
                            "action": {
                                "mitigate": {
                                    "action": "deny",
                                }
                            },
                        },
                        {
                            "id": "rule-rate-limit",
                            "name": "Rate limit login",
                            "active": True,
                            "conditionGroup": [
                                {
                                    "conditions": [
                                        {
                                            "type": "path",
                                            "op": "eq",
                                            "value": "/login",
                                        }
                                    ]
                                }
                            ],
                            "action": {
                                "mitigate": {
                                    "action": "deny",
                                    "rateLimit": {
                                        "algo": "fixed_window",
                                        "window": 60,
                                        "limit": 10,
                                    },
                                }
                            },
                        },
                    ],
                    "ips": [
                        {
                            "id": "ip-rule",
                            "ip": "203.0.113.7",
                            "action": "deny",
                        }
                    ],
                },
                "draft": None,
                "versions": [1],
            }
        )

        service._fetch_firewall_config(project)

        service._get.assert_called_once_with(
            "/v1/security/firewall/config/active",
            params={"projectId": PROJECT_ID, "teamId": TEAM_ID},
        )

        config = service.firewall_configs[PROJECT_ID]
        assert config.firewall_enabled is True
        assert config.managed_rulesets == {"owasp": {"active": True, "action": "deny"}}
        assert [rule["id"] for rule in config.custom_rules] == ["rule-custom"]
        assert [rule["id"] for rule in config.rate_limiting_rules] == [
            "rule-rate-limit"
        ]
        assert [rule["id"] for rule in config.ip_blocking_rules] == ["ip-rule"]

    def test_fetch_firewall_config_parses_crs_managed_rulesets(self):
        project = VercelProject(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            team_id=TEAM_ID,
            firewall_config_version="1",
        )
        service = Security.__new__(Security)
        service.firewall_configs = {}

        service._get = mock.MagicMock(
            return_value={
                "id": "waf_test",
                "version": 1,
                "firewallEnabled": True,
                "crs": {
                    "gen": {"active": True, "action": "log"},
                    "xss": {"active": True, "action": "deny"},
                    "php": {"active": False, "action": "log"},
                },
                "rules": [],
                "ips": [],
            }
        )

        service._fetch_firewall_config(project)

        config = service.firewall_configs[PROJECT_ID]
        assert config.firewall_enabled is True
        assert config.managed_rulesets == {
            "gen": {"active": True, "action": "log"},
            "xss": {"active": True, "action": "deny"},
        }

    def test_fetch_firewall_config_falls_back_to_wrapper_when_active_missing(self):
        project = VercelProject(id=PROJECT_ID, name=PROJECT_NAME, team_id=TEAM_ID)
        service = Security.__new__(Security)
        service.firewall_configs = {}

        service._get = mock.MagicMock(
            side_effect=[
                Exception("404 active config not found"),
                {"active": None, "draft": None, "versions": []},
            ]
        )

        service._fetch_firewall_config(project)

        assert service._get.call_args_list == [
            mock.call(
                "/v1/security/firewall/config/active",
                params={"projectId": PROJECT_ID, "teamId": TEAM_ID},
            ),
            mock.call(
                "/v1/security/firewall/config",
                params={"projectId": PROJECT_ID, "teamId": TEAM_ID},
            ),
        ]

        config = service.firewall_configs[PROJECT_ID]
        assert config.firewall_enabled is False
        assert config.managed_rulesets == {}
        assert config.custom_rules == []
        assert config.rate_limiting_rules == []
        assert config.ip_blocking_rules == []

    def test_fetch_firewall_config_uses_project_security_metadata_when_config_empty(
        self,
    ):
        project = VercelProject(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            team_id=TEAM_ID,
            firewall_enabled=True,
            firewall_config_version="42",
            managed_rules={
                "owasp": {"active": True, "action": "log"},
                "ai_bots": {"active": False, "action": "deny"},
            },
        )
        service = Security.__new__(Security)
        service.firewall_configs = {}

        service._get = mock.MagicMock(
            return_value={"active": None, "draft": None, "versions": []}
        )

        service._fetch_firewall_config(project)

        service._get.assert_called_once_with(
            "/v1/security/firewall/config/42",
            params={"projectId": PROJECT_ID, "teamId": TEAM_ID},
        )

        config = service.firewall_configs[PROJECT_ID]
        assert config.firewall_enabled is True
        assert config.managed_rulesets == {"owasp": {"active": True, "action": "log"}}
        assert config.custom_rules == []
        assert config.rate_limiting_rules == []
        assert config.ip_blocking_rules == []
