from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_priority_account_protection_enabled:
    def test_defender_no_email_tenant_settings(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.email_tenant_settings = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled import (
                defender_priority_account_protection_enabled,
            )

            check = defender_priority_account_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_defender_priority_account_protection_enabled(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled import (
                defender_priority_account_protection_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                EmailTenantSettings,
            )

            defender_client.email_tenant_settings = EmailTenantSettings(
                priority_account_protection_enabled=True,
            )

            check = defender_priority_account_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Priority account protection is enabled at the tenant level."
            )
            assert result[0].resource == defender_client.email_tenant_settings.dict()
            assert result[0].resource_name == "Email Tenant Settings"
            assert result[0].resource_id == "emailTenantSettings"
            assert result[0].location == "global"

    def test_defender_priority_account_protection_disabled(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled import (
                defender_priority_account_protection_enabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                EmailTenantSettings,
            )

            defender_client.email_tenant_settings = EmailTenantSettings(
                priority_account_protection_enabled=False,
            )

            check = defender_priority_account_protection_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Priority account protection is not enabled at the tenant level."
            )
            assert result[0].resource == defender_client.email_tenant_settings.dict()
            assert result[0].resource_name == "Email Tenant Settings"
            assert result[0].resource_id == "emailTenantSettings"
            assert result[0].location == "global"
