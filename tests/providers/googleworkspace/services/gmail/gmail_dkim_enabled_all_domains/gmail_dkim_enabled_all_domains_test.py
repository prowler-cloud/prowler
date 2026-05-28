from unittest.mock import patch

from prowler.providers.googleworkspace.models import GoogleWorkspaceIdentityInfo
from prowler.providers.googleworkspace.services.gmail.gmail_service import GmailPolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DELEGATED_USER,
    DOMAIN,
    ROOT_ORG_UNIT_ID,
    set_mocked_googleworkspace_provider,
)


class TestGmailDkimEnabledAllDomains:
    """Tests for the gmail_dkim_enabled_all_domains check.

    Since DKIM status is not exposed through any public Admin SDK/API,
    this check always returns MANUAL to prompt administrator verification.
    """

    def test_manual_status(self):
        """Check always returns MANUAL because DKIM status cannot be queried via API."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains import (
                gmail_dkim_enabled_all_domains,
            )

            mock_client.provider = mock_provider
            mock_client.policies = GmailPolicies()

            check = gmail_dkim_enabled_all_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert findings[0].resource_name == "Gmail Policies"
            assert findings[0].resource_id == "gmailPolicies"
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == GmailPolicies().dict()

    def test_manual_status_extended_contains_domain(self):
        """Verify the status_extended message references the tenant domain."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains import (
                gmail_dkim_enabled_all_domains,
            )

            mock_client.provider = mock_provider
            mock_client.policies = GmailPolicies()

            check = gmail_dkim_enabled_all_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert DOMAIN in findings[0].status_extended
            assert "cannot be automatically verified" in findings[0].status_extended
            assert f"google._domainkey.{DOMAIN}" in findings[0].status_extended

    def test_manual_status_extended_contains_admin_console_guidance(self):
        """Verify the status_extended message includes Admin Console verification instructions."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains import (
                gmail_dkim_enabled_all_domains,
            )

            mock_client.provider = mock_provider
            mock_client.policies = GmailPolicies()

            check = gmail_dkim_enabled_all_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert "Admin Console" in findings[0].status_extended
            assert "Authenticate email" in findings[0].status_extended
            assert "DKIM" in findings[0].status_extended

    def test_manual_status_with_custom_domain(self):
        """Verify the check correctly references a custom domain in the output."""
        custom_domain = "custom-org.io"
        custom_customer_id = "C9876543"
        mock_provider = set_mocked_googleworkspace_provider(
            identity=GoogleWorkspaceIdentityInfo(
                domain=custom_domain,
                customer_id=custom_customer_id,
                delegated_user=f"admin@{custom_domain}",
                root_org_unit_id=ROOT_ORG_UNIT_ID,
                profile="default",
            ),
        )

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains import (
                gmail_dkim_enabled_all_domains,
            )

            mock_client.provider = mock_provider
            mock_client.policies = GmailPolicies()

            check = gmail_dkim_enabled_all_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "MANUAL"
            assert findings[0].customer_id == custom_customer_id
            assert custom_domain in findings[0].status_extended
            assert f"google._domainkey.{custom_domain}" in findings[0].status_extended
            # Ensure default domain is NOT referenced
            assert DOMAIN not in findings[0].status_extended

    def test_single_finding_returned(self):
        """Check always produces exactly one finding (one MANUAL report per execution)."""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains.gmail_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.gmail.gmail_dkim_enabled_all_domains.gmail_dkim_enabled_all_domains import (
                gmail_dkim_enabled_all_domains,
            )

            mock_client.provider = mock_provider
            mock_client.policies = GmailPolicies()

            check = gmail_dkim_enabled_all_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status != "PASS"
            assert findings[0].status != "FAIL"
            assert findings[0].status == "MANUAL"
