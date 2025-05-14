from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_organization_mailtips_enabled:
    def test_no_organization(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled import (
                exchange_organization_mailtips_enabled,
            )

            check = exchange_organization_mailtips_enabled()
            result = check.execute()
            assert result == []

    def test_mailtips_not_fully_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled import (
                exchange_organization_mailtips_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.audit_config = {
                "recommended_mailtips_large_audience_threshold": 25
            }

            exchange_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                audit_disabled=False,
                oauth_enabled=True,
                mailtips_enabled=False,
                mailtips_external_recipient_enabled=False,
                mailtips_group_metrics_enabled=True,
                mailtips_large_audience_threshold=25,
            )

            check = exchange_organization_mailtips_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "MailTips are not fully enabled for Exchange Online."
            )
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
            assert result[0].resource == exchange_client.organization_config.dict()

    def test_mailtips_fully_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_mailtips_enabled.exchange_organization_mailtips_enabled import (
                exchange_organization_mailtips_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.audit_config = {
                "recommended_mailtips_large_audience_threshold": 25
            }

            exchange_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                audit_disabled=False,
                oauth_enabled=True,
                mailtips_enabled=True,
                mailtips_external_recipient_enabled=True,
                mailtips_group_metrics_enabled=True,
                mailtips_large_audience_threshold=25,
            )

            check = exchange_organization_mailtips_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "MailTips are fully enabled for Exchange Online."
            )
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
            assert result[0].resource == exchange_client.organization_config.dict()
