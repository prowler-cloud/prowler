from unittest.mock import patch

from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestGmailShortenerScanningEnabled:
    def test_pass(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled import (
                gmail_shortener_scanning_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_shortener_scanning=True)

            check = gmail_shortener_scanning_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "enabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled import (
                gmail_shortener_scanning_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_shortener_scanning=False)

            check = gmail_shortener_scanning_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "disabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled import (
                gmail_shortener_scanning_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_shortener_scanning=None)

            check = gmail_shortener_scanning_enabled()
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
                "prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_shortener_scanning_enabled.gmail_shortener_scanning_enabled import (
                gmail_shortener_scanning_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GmailPolicies()

            check = gmail_shortener_scanning_enabled()
            findings = check.execute()

            assert len(findings) == 0
