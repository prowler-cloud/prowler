from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_organization_reject_direct_send_enabled:
    def test_exchange_no_organization_config(self):
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
                "prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )

            check = exchange_organization_reject_direct_send_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_exchange_reject_direct_send_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                audit_disabled=False,
                oauth_enabled=True,
                mailtips_enabled=True,
                mailtips_external_recipient_enabled=True,
                mailtips_group_metrics_enabled=True,
                mailtips_large_audience_threshold=25,
                reject_direct_send=True,
            )

            check = exchange_organization_reject_direct_send_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Direct Send is rejected for the Exchange Online organization."
            )
            assert result[0].resource == exchange_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_exchange_reject_direct_send_disabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Organization,
            )

            exchange_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                audit_disabled=False,
                oauth_enabled=True,
                mailtips_enabled=True,
                mailtips_external_recipient_enabled=True,
                mailtips_group_metrics_enabled=True,
                mailtips_large_audience_threshold=25,
                reject_direct_send=False,
            )

            check = exchange_organization_reject_direct_send_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Direct Send is not rejected for the Exchange Online organization."
            )
            assert result[0].resource == exchange_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
