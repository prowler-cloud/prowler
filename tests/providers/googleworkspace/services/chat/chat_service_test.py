from unittest.mock import MagicMock, patch

from googleapiclient.errors import HttpError
from httplib2 import Response as HttpResponse

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    ROOT_ORG_UNIT_ID,
    set_mocked_googleworkspace_provider,
)


class TestChatService:
    def test_chat_fetch_policies_all_settings(self):
        """Test fetching all 4 Chat policy settings from Cloud Identity API"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/chat.chat_file_sharing",
                        "value": {
                            "externalFileSharing": "NO_FILES",
                            "internalFileSharing": "IMAGES_ONLY",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/chat.external_chat_restriction",
                        "value": {
                            "allowExternalChat": True,
                            "externalChatRestriction": "TRUSTED_DOMAINS",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/chat.chat_external_spaces",
                        "value": {
                            "enabled": True,
                            "domainAllowlistMode": "TRUSTED_DOMAINS",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/chat.chat_apps_access",
                        "value": {
                            "enableApps": False,
                            "enableWebhooks": False,
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is True
            assert chat.policies.external_file_sharing == "NO_FILES"
            assert chat.policies.internal_file_sharing == "IMAGES_ONLY"
            assert chat.policies.allow_external_chat is True
            assert chat.policies.external_chat_restriction == "TRUSTED_DOMAINS"
            assert chat.policies.external_spaces_enabled is True
            assert (
                chat.policies.external_spaces_domain_allowlist_mode == "TRUSTED_DOMAINS"
            )
            assert chat.policies.enable_apps is False
            assert chat.policies.enable_webhooks is False

    def test_chat_fetch_policies_empty_response(self):
        """Test handling empty policies response"""
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is True
            assert chat.policies.external_file_sharing is None
            assert chat.policies.allow_external_chat is None
            assert chat.policies.enable_apps is None
            assert chat.policies.enable_webhooks is None

    def test_chat_fetch_policies_api_error(self):
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is False
            assert chat.policies.external_file_sharing is None

    def test_chat_fetch_policies_build_service_returns_none(self):
        """Test early return when _build_service fails to construct the client"""
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is False
            assert chat.policies.external_file_sharing is None

    def test_chat_fetch_policies_execute_raises(self):
        """Test inner except handler when request.execute() raises during pagination"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_request = MagicMock()
        mock_request.execute.side_effect = Exception("Execute failed")
        mock_service.policies().list.return_value = mock_request

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is False
            assert chat.policies.external_file_sharing is None

    def test_chat_fetch_policies_ignores_ou_and_group_level(self):
        """Test that OU-level and group-level policies are skipped, only customer-level used"""
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
                    # Customer-level: no policyQuery → should be used
                    "setting": {
                        "type": "settings/chat.chat_apps_access",
                        "value": {"enableApps": False, "enableWebhooks": False},
                    }
                },
                {
                    # OU-level: has policyQuery.orgUnit → should be skipped
                    "policyQuery": {"orgUnit": "orgUnits/sales_team"},
                    "setting": {
                        "type": "settings/chat.chat_apps_access",
                        "value": {"enableApps": True, "enableWebhooks": True},
                    },
                },
                {
                    # Group-level: has policyQuery.group → should be skipped
                    "policyQuery": {"group": "groups/contractors"},
                    "setting": {
                        "type": "settings/chat.chat_file_sharing",
                        "value": {
                            "externalFileSharing": "ALL_FILES",
                            "internalFileSharing": "ALL_FILES",
                        },
                    },
                },
                {
                    # Customer-level: no policyQuery → should be used
                    "setting": {
                        "type": "settings/chat.chat_file_sharing",
                        "value": {
                            "externalFileSharing": "NO_FILES",
                            "internalFileSharing": "NO_FILES",
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is True
            assert chat.policies.enable_apps is False
            assert chat.policies.external_file_sharing == "NO_FILES"

    def test_chat_fetch_policies_accepts_root_ou(self):
        """Test that root-OU-scoped policies are accepted as customer-level"""
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
                    # Root OU: matches provider's root_org_unit_id → should be accepted
                    "policyQuery": {"orgUnit": f"orgUnits/{ROOT_ORG_UNIT_ID}"},
                    "setting": {
                        "type": "settings/chat.chat_apps_access",
                        "value": {"enableApps": False, "enableWebhooks": True},
                    },
                },
                {
                    # Sub-OU: different orgUnit → should be skipped
                    "policyQuery": {"orgUnit": "orgUnits/sub_ou_sales"},
                    "setting": {
                        "type": "settings/chat.chat_file_sharing",
                        "value": {
                            "externalFileSharing": "ALL_FILES",
                            "internalFileSharing": "ALL_FILES",
                        },
                    },
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
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            assert chat.policies_fetched is True
            # Root OU policy accepted
            assert chat.policies.enable_apps is False
            assert chat.policies.enable_webhooks is True
            # Sub-OU policy skipped
            assert chat.policies.external_file_sharing is None

    def test_chat_partial_fetch_marks_policies_fetched_false(self):
        """Regression: if page 1 returns valid data but page 2 raises an error,
        policies_fetched must be False even though some policy values were stored."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()

        # Page 1: returns valid Chat data
        page1_response = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/chat.chat_apps_access",
                        "value": {"enableApps": False, "enableWebhooks": False},
                    }
                },
            ]
        }

        # Page 2 request raises HttpError 429
        page1_request = MagicMock()
        page1_request.execute.return_value = page1_response

        page2_request = MagicMock()
        page2_request.execute.side_effect = HttpError(
            HttpResponse({"status": "429"}), b"Rate limit exceeded"
        )

        mock_service.policies().list.return_value = page1_request
        mock_service.policies().list_next.return_value = page2_request

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.chat.chat_service import (
                Chat,
            )

            chat = Chat(mock_provider)

            # Page 1 data was stored
            assert chat.policies.enable_apps is False
            # But policies_fetched must be False because page 2 failed
            assert chat.policies_fetched is False

    def test_chat_policies_model(self):
        """Test ChatPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.chat.chat_service import (
            ChatPolicies,
        )

        policies = ChatPolicies(
            external_file_sharing="NO_FILES",
            internal_file_sharing="IMAGES_ONLY",
            allow_external_chat=True,
            external_chat_restriction="TRUSTED_DOMAINS",
            external_spaces_enabled=True,
            external_spaces_domain_allowlist_mode="TRUSTED_DOMAINS",
            enable_apps=False,
            enable_webhooks=False,
        )

        assert policies.external_file_sharing == "NO_FILES"
        assert policies.internal_file_sharing == "IMAGES_ONLY"
        assert policies.allow_external_chat is True
        assert policies.external_chat_restriction == "TRUSTED_DOMAINS"
        assert policies.external_spaces_enabled is True
        assert policies.external_spaces_domain_allowlist_mode == "TRUSTED_DOMAINS"
        assert policies.enable_apps is False
        assert policies.enable_webhooks is False
