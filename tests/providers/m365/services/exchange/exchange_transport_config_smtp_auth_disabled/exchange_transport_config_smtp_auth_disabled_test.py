from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_transport_config_smtp_auth_disabled:
    def test_no_transport_config(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.transport_config = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled import (
                exchange_transport_config_smtp_auth_disabled,
            )

            check = exchange_transport_config_smtp_auth_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_smtp_auth_enabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_service import (
                TransportConfig,
            )
            from prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled import (
                exchange_transport_config_smtp_auth_disabled,
            )

            exchange_client.transport_config = TransportConfig(smtp_auth_disabled=False)

            check = exchange_transport_config_smtp_auth_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SMTP AUTH is enabled in the Exchange Online Transport Config."
            )
            assert result[0].resource == exchange_client.transport_config.dict()
            assert result[0].resource_name == "Transport Configuration"
            assert result[0].resource_id == "transport_config"
            assert result[0].location == "global"

    def test_smtp_auth_disabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_service import (
                TransportConfig,
            )
            from prowler.providers.m365.services.exchange.exchange_transport_config_smtp_auth_disabled.exchange_transport_config_smtp_auth_disabled import (
                exchange_transport_config_smtp_auth_disabled,
            )

            exchange_client.transport_config = TransportConfig(smtp_auth_disabled=True)

            check = exchange_transport_config_smtp_auth_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SMTP AUTH is disabled in the Exchange Online Transport Config."
            )
            assert result[0].resource == exchange_client.transport_config.dict()
            assert result[0].resource_name == "Transport Configuration"
            assert result[0].resource_id == "transport_config"
            assert result[0].location == "global"
