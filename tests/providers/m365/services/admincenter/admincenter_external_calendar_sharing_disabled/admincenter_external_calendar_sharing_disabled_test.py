from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_admincenter_external_calendar_sharing_disabled:
    def test_admincenter_no_sharing_policy(self):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN
        admincenter_client.sharing_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled import (
                admincenter_external_calendar_sharing_disabled,
            )

            check = admincenter_external_calendar_sharing_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_calendar_sharing_disabled(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled import (
                admincenter_external_calendar_sharing_disabled,
            )
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                SharingPolicy,
            )

            admincenter_client.sharing_policy = SharingPolicy(
                name="test-org",
                guid="org-guid",
                enabled=False,
            )

            check = admincenter_external_calendar_sharing_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "External calendar sharing is disabled at the organization level."
            )
            assert result[0].resource == admincenter_client.sharing_policy.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_admincenter_calendar_sharing_enabled(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_external_calendar_sharing_disabled.admincenter_external_calendar_sharing_disabled import (
                admincenter_external_calendar_sharing_disabled,
            )
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                SharingPolicy,
            )

            admincenter_client.sharing_policy = SharingPolicy(
                name="test-org",
                guid="org-guid",
                enabled=True,
            )

            check = admincenter_external_calendar_sharing_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "External calendar sharing is enabled at the organization level."
            )
            assert result[0].resource == admincenter_client.sharing_policy.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
