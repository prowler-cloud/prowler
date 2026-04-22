from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestGmailService:
    def test_gmail_fetch_policies_all_settings(self):
        """Test fetching all 10 Gmail policy settings from Cloud Identity API"""
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
                        "type": "settings/gmail.mail_delegation",
                        "value": {"enableMailDelegation": False},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.email_attachment_safety",
                        "value": {
                            "encryptedAttachmentProtectionConsequence": "SPAM_FOLDER",
                            "scriptAttachmentProtectionConsequence": "QUARANTINE",
                            "anomalousAttachmentProtectionConsequence": "WARNING",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.links_and_external_images",
                        "value": {
                            "enableShortenerScanning": True,
                            "enableExternalImageScanning": True,
                            "enableAggressiveWarningsOnUntrustedLinks": True,
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.spoofing_and_authentication",
                        "value": {
                            "domainSpoofingConsequence": "SPAM_FOLDER",
                            "employeeNameSpoofingConsequence": "SPAM_FOLDER",
                            "inboundDomainSpoofingConsequence": "QUARANTINE",
                            "unauthenticatedEmailConsequence": "WARNING",
                            "groupsSpoofingConsequence": "SPAM_FOLDER",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.pop_access",
                        "value": {"enablePopAccess": False},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.imap_access",
                        "value": {"enableImapAccess": False},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.auto_forwarding",
                        "value": {"enableAutoForwarding": False},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.per_user_outbound_gateway",
                        "value": {"allowUsersToUseExternalSmtpServers": False},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.enhanced_pre_delivery_message_scanning",
                        "value": {"enableImprovedSuspiciousContentDetection": True},
                    }
                },
                {
                    "setting": {
                        "type": "settings/gmail.comprehensive_mail_storage",
                        "value": {"ruleId": "rule-abc-123"},
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is True
            assert gmail.policies.enable_mail_delegation is False
            assert (
                gmail.policies.encrypted_attachment_protection_consequence
                == "SPAM_FOLDER"
            )
            assert (
                gmail.policies.script_attachment_protection_consequence == "QUARANTINE"
            )
            assert (
                gmail.policies.anomalous_attachment_protection_consequence == "WARNING"
            )
            assert gmail.policies.enable_shortener_scanning is True
            assert gmail.policies.enable_external_image_scanning is True
            assert gmail.policies.enable_aggressive_warnings_on_untrusted_links is True
            assert gmail.policies.domain_spoofing_consequence == "SPAM_FOLDER"
            assert gmail.policies.employee_name_spoofing_consequence == "SPAM_FOLDER"
            assert gmail.policies.inbound_domain_spoofing_consequence == "QUARANTINE"
            assert gmail.policies.unauthenticated_email_consequence == "WARNING"
            assert gmail.policies.groups_spoofing_consequence == "SPAM_FOLDER"
            assert gmail.policies.enable_pop_access is False
            assert gmail.policies.enable_imap_access is False
            assert gmail.policies.enable_auto_forwarding is False
            assert gmail.policies.allow_per_user_outbound_gateway is False
            assert gmail.policies.enable_enhanced_pre_delivery_scanning is True
            assert gmail.policies.comprehensive_mail_storage_enabled is True

    def test_gmail_fetch_policies_empty_response(self):
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is True
            assert gmail.policies.enable_mail_delegation is None
            assert gmail.policies.encrypted_attachment_protection_consequence is None
            assert gmail.policies.enable_pop_access is None
            assert gmail.policies.comprehensive_mail_storage_enabled is None

    def test_gmail_fetch_policies_api_error(self):
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is False
            assert gmail.policies.enable_mail_delegation is None

    def test_gmail_fetch_policies_build_service_returns_none(self):
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is False
            assert gmail.policies.enable_mail_delegation is None

    def test_gmail_fetch_policies_execute_raises(self):
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is False
            assert gmail.policies.enable_mail_delegation is None

    def test_gmail_fetch_policies_partial_fetch_still_marks_fetched(self):
        """Test that policies_fetched is True when data was stored before a pagination error (e.g. 429 rate limit)"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()

        # First page succeeds with policy data
        first_response = MagicMock()
        first_response.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/gmail.mail_delegation",
                        "value": {"enableMailDelegation": True},
                    }
                },
            ]
        }
        # Second page fails with rate limit
        second_request = MagicMock()
        second_request.execute.side_effect = Exception("429 Rate limit exceeded")

        mock_service.policies().list.return_value = first_response
        mock_service.policies().list_next.return_value = second_request

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            # Data was stored before the error, so policies_fetched should be True
            assert gmail.policies_fetched is True
            assert gmail.policies.enable_mail_delegation is True

    def test_gmail_fetch_policies_accepts_ou_level_as_fallback(self):
        """Test that OU-level policies are accepted when no customer-level exists for that setting type"""
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
                    # OU-level (root OU): no customer-level exists → should be used as fallback
                    "policyQuery": {"orgUnit": "orgUnits/root_ou_id"},
                    "setting": {
                        "type": "settings/gmail.mail_delegation",
                        "value": {"enableMailDelegation": False},
                    },
                },
                {
                    # Group-level: should always be skipped
                    "policyQuery": {"group": "groups/contractors"},
                    "setting": {
                        "type": "settings/gmail.auto_forwarding",
                        "value": {"enableAutoForwarding": True},
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is True
            # OU-level accepted as fallback
            assert gmail.policies.enable_mail_delegation is False
            # Group-level still skipped
            assert gmail.policies.enable_auto_forwarding is None

    def test_gmail_fetch_policies_customer_level_overrides_ou_level(self):
        """Test that customer-level policies take priority over OU-level, and group-level is always skipped"""
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
                        "type": "settings/gmail.mail_delegation",
                        "value": {"enableMailDelegation": False},
                    }
                },
                {
                    # OU-level: has policyQuery.orgUnit → should be skipped
                    "policyQuery": {"orgUnit": "orgUnits/sales_team"},
                    "setting": {
                        "type": "settings/gmail.mail_delegation",
                        "value": {"enableMailDelegation": True},
                    },
                },
                {
                    # Group-level: has policyQuery.group → should be skipped
                    "policyQuery": {"group": "groups/contractors"},
                    "setting": {
                        "type": "settings/gmail.auto_forwarding",
                        "value": {"enableAutoForwarding": True},
                    },
                },
                {
                    # Customer-level: no policyQuery → should be used
                    "setting": {
                        "type": "settings/gmail.auto_forwarding",
                        "value": {"enableAutoForwarding": False},
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
                "prowler.providers.googleworkspace.services.gmail.gmail_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_service import (
                Gmail,
            )

            gmail = Gmail(mock_provider)

            assert gmail.policies_fetched is True
            assert gmail.policies.enable_mail_delegation is False
            assert gmail.policies.enable_auto_forwarding is False

    def test_gmail_policies_model(self):
        """Test GmailPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.gmail.gmail_service import (
            GmailPolicies,
        )

        policies = GmailPolicies(
            enable_mail_delegation=False,
            encrypted_attachment_protection_consequence="SPAM_FOLDER",
            script_attachment_protection_consequence="QUARANTINE",
            anomalous_attachment_protection_consequence="WARNING",
            enable_shortener_scanning=True,
            enable_external_image_scanning=True,
            enable_aggressive_warnings_on_untrusted_links=True,
            domain_spoofing_consequence="SPAM_FOLDER",
            employee_name_spoofing_consequence="SPAM_FOLDER",
            inbound_domain_spoofing_consequence="QUARANTINE",
            unauthenticated_email_consequence="WARNING",
            groups_spoofing_consequence="SPAM_FOLDER",
            enable_pop_access=False,
            enable_imap_access=False,
            enable_auto_forwarding=False,
            allow_per_user_outbound_gateway=False,
            enable_enhanced_pre_delivery_scanning=True,
            comprehensive_mail_storage_enabled=True,
        )

        assert policies.enable_mail_delegation is False
        assert policies.encrypted_attachment_protection_consequence == "SPAM_FOLDER"
        assert policies.enable_shortener_scanning is True
        assert policies.domain_spoofing_consequence == "SPAM_FOLDER"
        assert policies.enable_pop_access is False
        assert policies.enable_auto_forwarding is False
        assert policies.enable_enhanced_pre_delivery_scanning is True
        assert policies.comprehensive_mail_storage_enabled is True
