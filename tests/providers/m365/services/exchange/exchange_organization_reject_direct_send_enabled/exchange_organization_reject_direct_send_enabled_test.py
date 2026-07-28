from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled"


def _make_org(reject_direct_send):
    from prowler.providers.m365.services.exchange.exchange_service import Organization

    return Organization(
        name="test-org",
        guid="org-guid",
        audit_disabled=False,
        oauth_enabled=True,
        mailtips_enabled=True,
        mailtips_external_recipient_enabled=True,
        mailtips_group_metrics_enabled=True,
        mailtips_large_audience_threshold=25,
        reject_direct_send=reject_direct_send,
    )


class Test_exchange_organization_reject_direct_send_enabled:
    def test_no_organization(self):
        exchange_client = mock.MagicMock()
        exchange_client.organization_config = None
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.exchange_client", new=exchange_client),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )

            assert exchange_organization_reject_direct_send_enabled().execute() == []

    def test_reject_direct_send_enabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.exchange_client", new=exchange_client),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )

            exchange_client.organization_config = _make_org(True)
            result = exchange_organization_reject_direct_send_enabled().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Direct Send is rejected for the Exchange Online organization."
            )

    def test_reject_direct_send_disabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.exchange_client", new=exchange_client),
        ):
            from prowler.providers.m365.services.exchange.exchange_organization_reject_direct_send_enabled.exchange_organization_reject_direct_send_enabled import (
                exchange_organization_reject_direct_send_enabled,
            )

            exchange_client.organization_config = _make_org(False)
            result = exchange_organization_reject_direct_send_enabled().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
