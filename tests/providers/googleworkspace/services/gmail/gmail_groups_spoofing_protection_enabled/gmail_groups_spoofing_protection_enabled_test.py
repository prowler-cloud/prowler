from unittest.mock import patch

from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestGmailGroupsSpoofingProtectionEnabled:
    def test_pass(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                detect_groups_spoofing=True,
                groups_spoofing_consequence="SPAM_FOLDER",
            )

            check = gmail_groups_spoofing_protection_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "all groups" in findings[0].status_extended
            assert "SPAM_FOLDER" in findings[0].status_extended
            assert findings[0].resource_name == "Gmail Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_private_groups_only(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                detect_groups_spoofing=True,
                groups_spoofing_visibility_type="PRIVATE_GROUPS_ONLY",
                groups_spoofing_consequence="SPAM_FOLDER",
            )

            check = gmail_groups_spoofing_protection_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "private groups only" in findings[0].status_extended
            assert "SPAM_FOLDER" in findings[0].status_extended

    def test_fail_no_action(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                detect_groups_spoofing=True,
                groups_spoofing_consequence="NO_ACTION",
            )

            check = gmail_groups_spoofing_protection_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "no action" in findings[0].status_extended

    def test_fail_warning_action(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                detect_groups_spoofing=True,
                groups_spoofing_consequence="WARNING",
            )

            check = gmail_groups_spoofing_protection_enabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "show a warning" in findings[0].status_extended

    def test_fail_protection_disabled(self):
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                detect_groups_spoofing=False,
                groups_spoofing_consequence="WARNING",
            )

            check = gmail_groups_spoofing_protection_enabled()
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
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies()

            check = gmail_groups_spoofing_protection_enabled()
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
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = GmailPolicies(
                service_state="DISABLED", detect_groups_spoofing=False
            )

            findings = gmail_groups_spoofing_protection_enabled().execute()

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
                "prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_groups_spoofing_protection_enabled.gmail_groups_spoofing_protection_enabled import (
                gmail_groups_spoofing_protection_enabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = GmailPolicies()

            check = gmail_groups_spoofing_protection_enabled()
            findings = check.execute()

            assert len(findings) == 0
