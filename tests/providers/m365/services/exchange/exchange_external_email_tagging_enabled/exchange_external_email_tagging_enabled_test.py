from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_external_email_tagging_enabled:
    def test_external_tagging_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled import (
                exchange_external_email_tagging_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                ExternalMailConfig,
            )

            exchange_client.external_mail_config = [
                ExternalMailConfig(identity="Org1", external_mail_tag_enabled=True)
            ]

            check = exchange_external_email_tagging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "External sender tagging is enabled for Exchange identity Org1."
            )
            assert result[0].resource == exchange_client.external_mail_config[0].dict()
            assert result[0].resource_name == "Org1"
            assert result[0].resource_id == "Org1"
            assert result[0].location == "global"

    def test_external_tagging_disabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled import (
                exchange_external_email_tagging_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                ExternalMailConfig,
            )

            exchange_client.external_mail_config = [
                ExternalMailConfig(identity="Org2", external_mail_tag_enabled=False)
            ]

            check = exchange_external_email_tagging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "External sender tagging is disabled for Exchange identity Org2."
            )
            assert result[0].resource == exchange_client.external_mail_config[0].dict()
            assert result[0].resource_name == "Org2"
            assert result[0].resource_id == "Org2"
            assert result[0].location == "global"

    def test_multiple_configs_mixed_status(self):
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
                "prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled import (
                exchange_external_email_tagging_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                ExternalMailConfig,
            )

            exchange_client.external_mail_config = [
                ExternalMailConfig(
                    identity="OrgEnabled", external_mail_tag_enabled=True
                ),
                ExternalMailConfig(
                    identity="OrgDisabled", external_mail_tag_enabled=False
                ),
            ]

            check = exchange_external_email_tagging_enabled()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "PASS"
            assert result[0].resource_name == "OrgEnabled"
            assert (
                result[0].status_extended
                == "External sender tagging is enabled for Exchange identity OrgEnabled."
            )

            assert result[1].status == "FAIL"
            assert result[1].resource_name == "OrgDisabled"
            assert (
                result[1].status_extended
                == "External sender tagging is disabled for Exchange identity OrgDisabled."
            )

    def test_no_mail_configs(self):
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
                "prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_external_email_tagging_enabled.exchange_external_email_tagging_enabled import (
                exchange_external_email_tagging_enabled,
            )

            exchange_client.external_mail_config = []

            check = exchange_external_email_tagging_enabled()
            result = check.execute()

            assert len(result) == 0
