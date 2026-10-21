from unittest.mock import patch

from prowler.providers.googleworkspace.services.chat.chat_service import ChatPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestChatAppsInstallationDisabled:
    def test_pass(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled import (
                chat_apps_installation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(enable_apps=False)

            check = chat_apps_installation_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Chat Policies"
            assert findings[0].resource_id == "chatPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == ChatPolicies(enable_apps=False).dict()

    def test_fail_enabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled import (
                chat_apps_installation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(enable_apps=True)

            check = chat_apps_installation_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_pass_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled import (
                chat_apps_installation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(enable_apps=None)

            check = chat_apps_installation_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended

    def test_pass_when_the_service_is_off_for_everyone(self):
        """A service that is off cannot expose anything, whatever its other settings say"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled import (
                chat_apps_installation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = ChatPolicies(
                service_state="DISABLED", enable_apps=True
            )

            findings = chat_apps_installation_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Google Chat is turned off for everyone in domain {DOMAIN}, "
                f"so Chat apps cannot be installed."
            )

    def test_no_findings_when_fetch_failed(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled.chat_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.chat.chat_apps_installation_disabled.chat_apps_installation_disabled import (
                chat_apps_installation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = ChatPolicies()

            check = chat_apps_installation_disabled()
            findings = check.execute()

            assert len(findings) == 0
