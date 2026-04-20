from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization"


class Test_entra_conditional_access_policy_p2_license_utilization:
    def test_no_premium_license_insight(self):
        """MANUAL when premium license insight data is unavailable (None)."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )

            entra_client.premium_license_insight = None

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not retrieve" in result[0].status_extended
            assert "P1 or P2" in result[0].status_extended
            assert "Reports.Read.All" in result[0].status_extended
            assert result[0].resource == {}
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_p2_covers_utilization(self):
        """PASS when P2 entitlements cover all risk-based CA users (regular + guest)."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=0,
                entitled_p2_license_count=50,
                entitled_total_license_count=50,
                p1_licenses_utilized=20,
                p2_licenses_utilized=35,
            )

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license entitlements (50) cover all risk-based Conditional Access users (35)."
            )
            assert (
                result[0].resource == entra_client.premium_license_insight.dict()
            )
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_p1_only_does_not_cover_p2_utilization(self):
        """FAIL: P1 entitlements do not include P2 features."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=200,
                entitled_p2_license_count=0,
                entitled_total_license_count=200,
                p1_licenses_utilized=150,
                p2_licenses_utilized=10,
            )

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "P2 license entitlements (0) do not cover all risk-based Conditional Access users (10)."
            )
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_licenses_insufficient_with_guests(self):
        """FAIL when guest risk-based CA users push utilization above the entitled count."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=0,
                entitled_p2_license_count=30,
                entitled_total_license_count=30,
                p1_licenses_utilized=0,
                p2_licenses_utilized=35,
            )

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "P2 license entitlements (30) do not cover all risk-based Conditional Access users (35)."
            )
            assert (
                result[0].resource == entra_client.premium_license_insight.dict()
            )
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_p1_utilization_does_not_affect_p2_check(self):
        """P1 CA usage is ignored by this check; only risk-based (P2) is evaluated."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=0,
                entitled_p2_license_count=10,
                entitled_total_license_count=10,
                p1_licenses_utilized=999,
                p2_licenses_utilized=5,
            )

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license entitlements (10) cover all risk-based Conditional Access users (5)."
            )

    def test_zero_licenses_zero_users(self):
        """PASS when both P2 license count and risk-based utilization are zero."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p2_license_utilization.entra_conditional_access_policy_p2_license_utilization import (
                entra_conditional_access_policy_p2_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight()

            check = entra_conditional_access_policy_p2_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "P2 license entitlements (0) cover all risk-based Conditional Access users (0)."
            )
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"
