from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestRulesService:
    def test_fetch_fully_configured_rule(self):
        """Test fetching a system-defined alert rule with all 3 conditions met."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/rule.system_defined_alerts",
                        "value": {
                            "displayName": "Suspicious login",
                            "description": "Google detected a suspicious sign-in.",
                            "action": {
                                "alertCenterAction": {
                                    "recipients": [{"allSuperAdmins": True}],
                                    "alertCenterConfig": {"severity": "LOW"},
                                }
                            },
                            "state": "ACTIVE",
                        },
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            assert rules.policies_fetched is True
            assert len(rules.system_defined_alerts) == 8

            suspicious_login = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "Suspicious login"
            )
            assert suspicious_login.state == "ACTIVE"
            assert suspicious_login.email_notifications_enabled is True
            assert suspicious_login.all_super_admins is True
            assert suspicious_login.severity == "LOW"

    def test_fetch_rule_without_email_notifications(self):
        """Test a rule that is ACTIVE but has no email recipients configured."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/rule.system_defined_alerts",
                        "value": {
                            "displayName": "Government-backed attacks",
                            "description": "Google believes a user is targeted.",
                            "action": {
                                "alertCenterAction": {
                                    "alertCenterConfig": {"severity": "HIGH"}
                                }
                            },
                            "state": "ACTIVE",
                        },
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            gov_attack = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "Government-backed attacks"
            )
            assert gov_attack.state == "ACTIVE"
            assert gov_attack.email_notifications_enabled is False
            assert gov_attack.all_super_admins is False
            assert gov_attack.severity == "HIGH"

    def test_empty_response_fills_defaults(self):
        """Test that all 8 rules get default values when API returns nothing."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {"policies": []}
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            assert rules.policies_fetched is True
            assert len(rules.system_defined_alerts) == 8

            # All defaults should have no severity (not returned by API)
            for alert in rules.system_defined_alerts:
                assert alert.severity is None

            # INACTIVE defaults: no email notifications
            password_changed = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "User's password changed"
            )
            assert password_changed.state == "INACTIVE"
            assert password_changed.email_notifications_enabled is False
            assert password_changed.all_super_admins is False

            admin_privilege = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "User granted Admin privilege"
            )
            assert admin_privilege.state == "INACTIVE"
            assert admin_privilege.email_notifications_enabled is False
            assert admin_privilege.all_super_admins is False

            # ACTIVE defaults: email notifications ON with all super admins
            suspicious_login = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "Suspicious login"
            )
            assert suspicious_login.state == "ACTIVE"
            assert suspicious_login.email_notifications_enabled is True
            assert suspicious_login.all_super_admins is True

            gov_attacks = next(
                a
                for a in rules.system_defined_alerts
                if a.display_name == "Government-backed attacks"
            )
            assert gov_attacks.state == "ACTIVE"
            assert gov_attacks.email_notifications_enabled is True
            assert gov_attacks.all_super_admins is True

    def test_api_error_sets_policies_fetched_false(self):
        """Test that API errors result in policies_fetched being False."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_service.policies().list.side_effect = Exception("API Error")

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            assert rules.policies_fetched is False

    def test_build_service_returns_none(self):
        """Test early return when _build_service fails."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            assert rules.policies_fetched is False
            assert len(rules.system_defined_alerts) == 0

    def test_non_cis_rules_are_ignored(self):
        """Test that system-defined rules not in the 8 CIS rules are ignored."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/rule.system_defined_alerts",
                        "value": {
                            "displayName": "Device compromised",
                            "description": "A device has been compromised.",
                            "state": "ACTIVE",
                        },
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.rules.rules_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.rules.rules_service import (
                Rules,
            )

            rules = Rules(mock_provider)

            assert len(rules.system_defined_alerts) == 8
            names = {a.display_name for a in rules.system_defined_alerts}
            assert "Device compromised" not in names

    def test_system_defined_alert_model(self):
        """Test SystemDefinedAlert Pydantic model defaults."""
        from prowler.providers.googleworkspace.services.rules.rules_service import (
            SystemDefinedAlert,
        )

        alert = SystemDefinedAlert(display_name="Test rule")
        assert alert.state == "INACTIVE"
        assert alert.severity is None
        assert alert.email_notifications_enabled is False
        assert alert.all_super_admins is False
