from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_admincenter_organization_customer_lockbox_enabled:
    def test_admincenter_no_org_config(self):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN
        admincenter_client.organization_config = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled import (
                admincenter_organization_customer_lockbox_enabled,
            )

            check = admincenter_organization_customer_lockbox_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_customer_lockbox_enabled(self):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled import (
                admincenter_organization_customer_lockbox_enabled,
            )
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=True,
            )

            check = admincenter_organization_customer_lockbox_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Customer Lockbox is enabled at organization level."
            )
            assert result[0].resource == admincenter_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_admincenter_customer_lockbox_disabled(self):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_organization_customer_lockbox_enabled.admincenter_organization_customer_lockbox_enabled import (
                admincenter_organization_customer_lockbox_enabled,
            )
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
            )

            check = admincenter_organization_customer_lockbox_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Customer Lockbox is not enabled at organization level."
            )
            assert result[0].resource == admincenter_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
