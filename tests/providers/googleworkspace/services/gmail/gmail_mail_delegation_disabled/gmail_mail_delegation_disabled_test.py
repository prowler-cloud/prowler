from unittest.mock import patch

from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestGmailMailDelegationDisabled:
    def test_pass_delegation_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled import (
                gmail_mail_delegation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_mail_delegation=False)

            check = gmail_mail_delegation_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_delegation_enabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled import (
                gmail_mail_delegation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_mail_delegation=True)

            check = gmail_mail_delegation_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled import (
                gmail_mail_delegation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(enable_mail_delegation=None)

            check = gmail_mail_delegation_disabled()
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
                "prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_mail_delegation_disabled.gmail_mail_delegation_disabled import (
                gmail_mail_delegation_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GmailPolicies()

            check = gmail_mail_delegation_disabled()
            findings = check.execute()

            assert len(findings) == 0
