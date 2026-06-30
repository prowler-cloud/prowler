from unittest import mock

from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_exchange_organization_delicensing_resiliency_enabled_fixer:
    def test_creates_new_powershell_session(self):
        created_session = mock.MagicMock()
        created_session.connect_exchange_online.return_value = True
        created_session.execute.return_value = ""

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled_fixer.M365PowerShell",
                return_value=created_session,
            ) as mocked_powershell,
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled_fixer import (
                fixer,
            )

            assert fixer()
            mocked_powershell.assert_called_once()
            created_session.connect_exchange_online.assert_called_once()
            created_session.execute.assert_any_call(
                "Set-OrganizationConfig -DelayedDelicensingEnabled $true",
                timeout=30,
            )
            created_session.close.assert_called_once()

    def test_logs_power_shell_execution_error(self):
        created_session = mock.MagicMock()
        created_session.connect_exchange_online.return_value = True
        created_session.execute.return_value = "Access is denied."

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled_fixer.M365PowerShell",
                return_value=created_session,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled_fixer.logger.error",
            ) as mocked_logger_error,
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_delicensing_resiliency_enabled.exchange_organization_delicensing_resiliency_enabled_fixer import (
                fixer,
            )

            assert not fixer()
            mocked_logger_error.assert_any_call(
                'PowerShell execution failed while running "Set-OrganizationConfig -DelayedDelicensingEnabled $true": Access is denied.'
            )
            created_session.close.assert_called_once()
