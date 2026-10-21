from unittest.mock import patch

from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestGmailUntrustedLinkWarningsEnabled:
    def test_pass(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled import (
                gmail_untrusted_link_warnings_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_aggressive_warnings_on_untrusted_links=True
            )

            check = gmail_untrusted_link_warnings_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "enabled" in findings[0].status_extended
            assert findings[0].resource_name == "Gmail Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled import (
                gmail_untrusted_link_warnings_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_aggressive_warnings_on_untrusted_links=False
            )

            check = gmail_untrusted_link_warnings_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "disabled" in findings[0].status_extended

    def test_fail_insecure_default(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled import (
                gmail_untrusted_link_warnings_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_aggressive_warnings_on_untrusted_links=None
            )

            check = gmail_untrusted_link_warnings_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "insecure default" in findings[0].status_extended

    def test_pass_when_the_service_is_off_for_everyone(self):
        """A setting that only acts while the service is on has no effect once the service is off"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled import (
                gmail_untrusted_link_warnings_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                service_state="DISABLED",
                enable_aggressive_warnings_on_untrusted_links=False,
            )

            findings = gmail_untrusted_link_warnings_enabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Gmail is turned off for everyone in domain {DOMAIN}, "
                f"so no user mailbox receives mail through Gmail."
            )

    def test_no_findings_when_fetch_failed(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_untrusted_link_warnings_enabled.gmail_untrusted_link_warnings_enabled import (
                gmail_untrusted_link_warnings_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GmailPolicies()

            check = gmail_untrusted_link_warnings_enabled()
            findings = check.execute()

            assert len(findings) == 0
