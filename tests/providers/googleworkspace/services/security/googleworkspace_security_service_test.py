from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestSecurityService:
    def test_fetch_policies_all_security_settings(self):
        """Test fetching security policies from Cloud Identity API"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()

        # First call: security.* settings
        mock_security_list = MagicMock()
        mock_security_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/security.two_step_verification_enforcement",
                        "value": {
                            "enforcedFrom": "2026-05-25T15:27:52.352Z",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.two_step_verification_enforcement_factor",
                        "value": {
                            "allowedSignInFactorSet": "ALL",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.super_admin_account_recovery",
                        "value": {
                            "enableAccountRecovery": True,
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.password",
                        "value": {
                            "allowedStrength": "STRONG",
                            "minimumLength": 8,
                            "maximumLength": 100,
                            "enforceRequirementsAtLogin": False,
                            "allowReuse": False,
                            "expirationDuration": "0s",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.session_controls",
                        "value": {
                            "webSessionDuration": "1209600s",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.less_secure_apps",
                        "value": {
                            "allowLessSecureApps": False,
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.advanced_protection_program",
                        "value": {
                            "enableAdvancedProtectionSelfEnrollment": True,
                            "securityCodeOption": "CODES_NOT_ALLOWED",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/security.login_challenges",
                        "value": {
                            "enableEmployeeIdChallenge": False,
                        },
                    }
                },
            ]
        }

        # Second call: api_controls.* settings
        mock_api_controls_list = MagicMock()
        mock_api_controls_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/api_controls.internal_apps",
                        "value": {
                            "trustInternalApps": True,
                        },
                    }
                },
            ]
        }

        # Third call: rule.dlp
        mock_dlp_list = MagicMock()
        mock_dlp_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/rule.dlp",
                        "value": {
                            "displayName": "PII Detection",
                            "triggers": ["google.workspace.drive.file.v1.share"],
                            "state": "ACTIVE",
                        },
                    }
                },
            ]
        }

        mock_service.policies().list.side_effect = [
            mock_security_list,
            mock_api_controls_list,
            mock_dlp_list,
        ]
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.security.security_service import (
                Security,
            )

            security = Security(mock_provider)

            assert security.policies_fetched is True
            assert security.policies.two_sv_enforced_from == "2026-05-25T15:27:52.352Z"
            assert security.policies.two_sv_allowed_factor_set == "ALL"
            assert security.policies.super_admin_recovery_enabled is True
            assert security.policies.password_minimum_length == 8
            assert security.policies.password_allowed_strength == "STRONG"
            assert security.policies.password_allow_reuse is False
            assert security.policies.password_enforce_at_login is False
            assert security.policies.password_expiration_duration == "0s"
            assert security.policies.web_session_duration == "1209600s"
            assert security.policies.less_secure_apps_allowed is False
            assert security.policies.advanced_protection_enrollment is True
            assert (
                security.policies.advanced_protection_security_code_option
                == "CODES_NOT_ALLOWED"
            )
            assert security.policies.login_challenge_employee_id is False
            assert security.policies.trust_internal_apps is True
            assert security.policies.dlp_drive_rules_exist is True

    def test_fetch_policies_empty_response(self):
        """Test handling empty policies response across all namespaces"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_empty = MagicMock()
        mock_empty.execute.return_value = {"policies": []}
        mock_service.policies().list.side_effect = [
            mock_empty,
            mock_empty,
            mock_empty,
        ]
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.security.security_service import (
                Security,
            )

            security = Security(mock_provider)

            assert security.policies_fetched is True
            assert security.policies.two_sv_enforced_from is None
            assert security.policies.super_admin_recovery_enabled is None
            assert security.policies.password_minimum_length is None
            assert security.policies.web_session_duration is None
            assert security.policies.less_secure_apps_allowed is None
            assert security.policies.trust_internal_apps is None
            assert security.policies.dlp_drive_rules_exist is None

    def test_fetch_policies_api_error(self):
        """Test handling of API errors during policy fetch"""
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
                "prowler.providers.googleworkspace.services.security.security_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.security.security_service import (
                Security,
            )

            security = Security(mock_provider)

            assert security.policies_fetched is False

    def test_fetch_policies_build_service_returns_none(self):
        """Test early return when _build_service fails"""
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
                "prowler.providers.googleworkspace.services.security.security_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.security.security_service import (
                Security,
            )

            security = Security(mock_provider)

            assert security.policies_fetched is False

    def test_dlp_rule_without_drive_trigger_ignored(self):
        """Test that DLP rules without Drive triggers don't set dlp_drive_rules_exist"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_empty = MagicMock()
        mock_empty.execute.return_value = {"policies": []}

        mock_dlp_list = MagicMock()
        mock_dlp_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/rule.dlp",
                        "value": {
                            "displayName": "Gmail Only Rule",
                            "triggers": ["google.workspace.gmail.email.v1.send"],
                            "state": "ACTIVE",
                        },
                    }
                },
            ]
        }

        mock_service.policies().list.side_effect = [
            mock_empty,
            mock_empty,
            mock_dlp_list,
        ]
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.security.security_service import (
                Security,
            )

            security = Security(mock_provider)

            assert security.policies_fetched is True
            assert security.policies.dlp_drive_rules_exist is None

    def test_security_policies_model(self):
        """Test SecurityPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.security.security_service import (
            SecurityPolicies,
        )

        policies = SecurityPolicies(
            two_sv_enforced_from="2026-05-25T15:27:52.352Z",
            super_admin_recovery_enabled=False,
            password_minimum_length=14,
            web_session_duration="43200s",
        )

        assert policies.two_sv_enforced_from == "2026-05-25T15:27:52.352Z"
        assert policies.super_admin_recovery_enabled is False
        assert policies.password_minimum_length == 14
        assert policies.web_session_duration == "43200s"
