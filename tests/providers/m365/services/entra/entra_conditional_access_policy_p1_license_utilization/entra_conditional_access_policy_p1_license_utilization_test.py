from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization"


class Test_entra_conditional_access_policy_p1_license_utilization:
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )

            entra_client.premium_license_insight = None

            check = entra_conditional_access_policy_p1_license_utilization()
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

    def test_p1_only_covers_utilization(self):
        """PASS when P1 entitlements alone cover all CA users (regular + guest)."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=100,
                entitled_p2_license_count=0,
                conditional_access_user_count=60,
                conditional_access_guest_user_count=10,
                total_license_count=100,
                conditional_access_users_count=70,
            )

            check = entra_conditional_access_policy_p1_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Premium license entitlements (100) cover all Conditional Access users (70)."
            )
            assert result[0].resource == entra_client.premium_license_insight.dict()
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_p1_plus_p2_covers_utilization(self):
        """PASS when combined P1 + P2 entitlements cover all CA users."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=50,
                entitled_p2_license_count=50,
                conditional_access_user_count=60,
                conditional_access_guest_user_count=20,
                total_license_count=100,
                conditional_access_users_count=80,
            )

            check = entra_conditional_access_policy_p1_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Premium license entitlements (100) cover all Conditional Access users (80)."
            )
            assert result[0].resource == entra_client.premium_license_insight.dict()
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_p2_only_covers_utilization(self):
        """PASS when only P2 licenses are entitled (P2 includes P1)."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=0,
                entitled_p2_license_count=150,
                conditional_access_user_count=100,
                conditional_access_guest_user_count=20,
                total_license_count=150,
                conditional_access_users_count=120,
            )

            check = entra_conditional_access_policy_p1_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Premium license entitlements (150) cover all Conditional Access users (120)."
            )
            assert result[0].resource == entra_client.premium_license_insight.dict()
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_licenses_insufficient_with_guests(self):
        """FAIL when guest CA users push utilization above the entitled count."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight(
                entitled_p1_license_count=30,
                entitled_p2_license_count=0,
                conditional_access_user_count=25,
                conditional_access_guest_user_count=10,
                total_license_count=30,
                conditional_access_users_count=35,
            )

            check = entra_conditional_access_policy_p1_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Premium license entitlements (30) do not cover all Conditional Access users (35)."
            )
            assert result[0].resource == entra_client.premium_license_insight.dict()
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"

    def test_zero_licenses_zero_users(self):
        """PASS when both license count and utilization are zero."""
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
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_p1_license_utilization.entra_conditional_access_policy_p1_license_utilization import (
                entra_conditional_access_policy_p1_license_utilization,
            )
            from prowler.providers.m365.services.entra.entra_service import (
                PremiumLicenseInsight,
            )

            entra_client.premium_license_insight = PremiumLicenseInsight()

            check = entra_conditional_access_policy_p1_license_utilization()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Premium license entitlements (0) cover all Conditional Access users (0)."
            )
            assert result[0].resource_name == "Premium License Insight"
            assert result[0].resource_id == "azureADPremiumLicenseInsight"
            assert result[0].location == "global"
