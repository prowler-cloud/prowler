from unittest.mock import patch

from prowler.providers.googleworkspace.services.sites.sites_service import (
    SitesPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSitesServiceDisabled:
    def test_pass_service_disabled(self):
        """Test PASS when Sites service is disabled (OFF for everyone)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled.sites_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled import (
                sites_service_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SitesPolicies(service_state="DISABLED")

            check = sites_service_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Sites Policies"
            assert findings[0].resource_id == "sitesPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_service_enabled(self):
        """Test FAIL when Sites service is enabled (ON for everyone)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled.sites_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled import (
                sites_service_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SitesPolicies(service_state="ENABLED")

            check = sites_service_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) - Google default is ON (insecure)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled.sites_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled import (
                sites_service_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SitesPolicies(service_state=None)

            check = sites_service_disabled()
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
                "prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled.sites_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.sites.sites_service_disabled.sites_service_disabled import (
                sites_service_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SitesPolicies()

            check = sites_service_disabled()
            findings = check.execute()

            assert len(findings) == 0
