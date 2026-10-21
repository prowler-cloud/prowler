from unittest.mock import patch

from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestGmailPopImapAccessDisabled:
    def test_pass_both_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_pop_access=False, enable_imap_access=False
            )

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Gmail Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_both_enabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_pop_access=True, enable_imap_access=True
            )

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "POP" in findings[0].status_extended
            assert "IMAP" in findings[0].status_extended

    def test_fail_pop_enabled_only(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_pop_access=True, enable_imap_access=False
            )

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "POP" in findings[0].status_extended

    def test_fail_imap_enabled_only(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_pop_access=False, enable_imap_access=True
            )

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "IMAP" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                enable_pop_access=None, enable_imap_access=None
            )

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_pass_when_the_service_is_off_for_everyone(self):
        """A setting that only acts while the service is on has no effect once the service is off"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                service_state="DISABLED",
                enable_pop_access=True,
                enable_imap_access=True,
            )

            findings = gmail_pop_imap_access_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Gmail is turned off for everyone in domain {DOMAIN}, "
                f"so no mailbox can be reached over POP or IMAP."
            )

    def test_no_findings_when_fetch_failed(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_pop_imap_access_disabled.gmail_pop_imap_access_disabled import (
                gmail_pop_imap_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GmailPolicies()

            check = gmail_pop_imap_access_disabled()
            findings = check.execute()

            assert len(findings) == 0
