from unittest.mock import patch

from prowler.providers.googleworkspace.services.chat.chat_service import ChatPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestChatInternalFileSharingDisabled:
    def test_pass(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled import (
                chat_internal_file_sharing_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(internal_file_sharing="NO_FILES")

            check = chat_internal_file_sharing_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].resource_id == CUSTOMER_ID
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == mock_provider.domain_resource.dict()

    def test_fail_all_files(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled import (
                chat_internal_file_sharing_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(internal_file_sharing="ALL_FILES")

            check = chat_internal_file_sharing_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ALL_FILES" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled import (
                chat_internal_file_sharing_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(internal_file_sharing=None)

            check = chat_internal_file_sharing_disabled()
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
                "prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_internal_file_sharing_disabled.chat_internal_file_sharing_disabled import (
                chat_internal_file_sharing_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = ChatPolicies()

            check = chat_internal_file_sharing_disabled()
            findings = check.execute()

            assert len(findings) == 0
