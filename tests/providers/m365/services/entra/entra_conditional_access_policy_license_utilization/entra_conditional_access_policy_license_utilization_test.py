from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    PremiumLicenseInsight,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_conditional_access_policy_license_utilization:
    """Tests for the entra_conditional_access_policy_license_utilization check.

    Validates that P2 license utilization is correctly compared against entitled
    P2 licenses, covering PASS, FAIL, and edge-case scenarios.
    """

    def test_no_license_insight_data(self):
        """FAIL when premium license insight data could not be retrieved."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = None

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Could not retrieve premium license insight data, ensure the required permissions are granted."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_no_p2_licenses_entitled_with_utilization(self):
        """FAIL when no P2 licenses are entitled but users consume P2 features."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                total_user_count=100,
                entitled_p1_license_count=50,
                entitled_p2_license_count=0,
                p1_licenses_utilized=30,
                p2_licenses_utilized=10,
            )

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No P2 licenses are entitled but 10 user(s) are consuming P2 features."
            )
            assert result[0].location == "global"

    def test_p2_utilization_exceeds_entitlement(self):
        """FAIL when P2 license utilization exceeds the number of entitled licenses."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                total_user_count=100,
                entitled_p1_license_count=50,
                entitled_p2_license_count=10,
                p1_licenses_utilized=30,
                p2_licenses_utilized=15,
            )

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "P2 license utilization (15) exceeds entitled P2 licenses (10), 5 user(s) are consuming P2 features without a license."
            )
            assert result[0].location == "global"

    def test_p2_utilization_within_entitlement(self):
        """PASS when P2 license utilization is within the entitled count."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                total_user_count=100,
                entitled_p1_license_count=50,
                entitled_p2_license_count=20,
                p1_licenses_utilized=30,
                p2_licenses_utilized=15,
            )

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license utilization (15) is within entitled P2 licenses (20)."
            )
            assert result[0].location == "global"

    def test_p2_utilization_zero_with_licenses(self):
        """PASS when P2 licenses are entitled and no users consume P2 features."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                total_user_count=100,
                entitled_p1_license_count=50,
                entitled_p2_license_count=20,
                p1_licenses_utilized=30,
                p2_licenses_utilized=0,
            )

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license utilization (0) is within entitled P2 licenses (20)."
            )
            assert result[0].location == "global"

    def test_no_p2_licenses_entitled_no_utilization(self):
        """PASS when no P2 licenses are entitled and no users consume P2 features."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_license_utilization.entra_conditional_access_policy_license_utilization import (
                entra_conditional_access_policy_license_utilization,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                total_user_count=100,
                entitled_p1_license_count=50,
                entitled_p2_license_count=0,
                p1_licenses_utilized=30,
                p2_licenses_utilized=0,
            )

            check = entra_conditional_access_policy_license_utilization()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license utilization (0) is within entitled P2 licenses (0)."
            )
            assert result[0].location == "global"
