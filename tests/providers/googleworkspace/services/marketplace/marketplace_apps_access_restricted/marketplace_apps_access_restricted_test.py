from unittest.mock import patch

from prowler.providers.googleworkspace.services.marketplace.marketplace_service import (
    MarketplacePolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestMarketplaceAppsAccessRestricted:
    def test_pass_allow_listed_apps(self):
        """Test PASS when Marketplace access is restricted to admin-approved apps"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted.marketplace_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted import (
                marketplace_apps_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = MarketplacePolicies(access_level="ALLOW_LISTED_APPS")

            check = marketplace_apps_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "restricted" in findings[0].status_extended
            assert findings[0].resource_name == "Marketplace Policies"
            assert findings[0].resource_id == "marketplacePolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_allow_none(self):
        """Test PASS when Marketplace app installation is fully blocked"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted.marketplace_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted import (
                marketplace_apps_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = MarketplacePolicies(access_level="ALLOW_NONE")

            check = marketplace_apps_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "blocked" in findings[0].status_extended

    def test_fail_allow_all(self):
        """Test FAIL when Marketplace allows all apps"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted.marketplace_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted import (
                marketplace_apps_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = MarketplacePolicies(access_level="ALLOW_ALL")

            check = marketplace_apps_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "any app" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) - Google default is ALLOW_ALL (insecure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted.marketplace_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted import (
                marketplace_apps_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = MarketplacePolicies(access_level=None)

            check = marketplace_apps_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted.marketplace_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.marketplace.marketplace_apps_access_restricted.marketplace_apps_access_restricted import (
                marketplace_apps_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = MarketplacePolicies()

            check = marketplace_apps_access_restricted()
            findings = check.execute()

            assert len(findings) == 0
