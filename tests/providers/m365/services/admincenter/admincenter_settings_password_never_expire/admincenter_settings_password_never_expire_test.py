from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_admincenter_settings_password_never_expire:
    def test_admincenter_no_domains(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            admincenter_client.password_policy = None

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_domain_password_expire(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                PasswordPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            admincenter_client.password_policy = PasswordPolicy(
                password_validity_period=5
            )

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Tenant Password policy does not have a Password never expires policy."
            )
            assert result[0].resource == admincenter_client.password_policy.dict()
            assert result[0].resource_name == "Password Policy"
            assert result[0].resource_id == "passwordPolicy"
            assert result[0].location == "global"

    def test_admincenter_password_not_expire(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                PasswordPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_settings_password_never_expire.admincenter_settings_password_never_expire import (
                admincenter_settings_password_never_expire,
            )

            admincenter_client.password_policy = PasswordPolicy(
                password_validity_period=2147483647
            )

            check = admincenter_settings_password_never_expire()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Tenant Password policy is set to never expire."
            )
            assert result[0].resource == admincenter_client.password_policy.dict()
            assert result[0].resource_name == "Password Policy"
            assert result[0].resource_id == "passwordPolicy"
            assert result[0].location == "global"
