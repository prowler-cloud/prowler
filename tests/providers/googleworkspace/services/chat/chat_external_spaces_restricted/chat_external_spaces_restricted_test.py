from unittest.mock import patch

from prowler.providers.googleworkspace.services.chat.chat_service import ChatPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestChatExternalSpacesRestricted:
    def test_pass_spaces_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted import (
                chat_external_spaces_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(external_spaces_enabled=False)

            check = chat_external_spaces_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Chat Policies"
            assert findings[0].resource_id == "chatPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert (
                findings[0].resource
                == ChatPolicies(external_spaces_enabled=False).dict()
            )

    def test_pass_trusted_domains(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted import (
                chat_external_spaces_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(
                external_spaces_enabled=True,
                external_spaces_domain_allowlist_mode="TRUSTED_DOMAINS",
            )

            check = chat_external_spaces_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "restricted to allowed domains" in findings[0].status_extended

    def test_fail_all_domains(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted import (
                chat_external_spaces_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(
                external_spaces_enabled=True,
                external_spaces_domain_allowlist_mode="ALL_DOMAINS",
            )

            check = chat_external_spaces_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not restricted" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted import (
                chat_external_spaces_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies()

            check = chat_external_spaces_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_external_spaces_restricted.chat_external_spaces_restricted import (
                chat_external_spaces_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = ChatPolicies()

            check = chat_external_spaces_restricted()
            findings = check.execute()

            assert len(findings) == 0
