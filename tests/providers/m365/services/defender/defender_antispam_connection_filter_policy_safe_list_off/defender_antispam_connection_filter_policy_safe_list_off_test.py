from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_connection_filter_policy_safe_list_off:
    def test_safe_list_off(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off import (
                defender_antispam_connection_filter_policy_safe_list_off,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                ConnectionFilterPolicy,
            )

            defender_client.connection_filter_policy = ConnectionFilterPolicy(
                ip_allow_list=[],
                identity="Default",
                enable_safe_list=False,
            )

            check = defender_antispam_connection_filter_policy_safe_list_off()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Safe List is off in the Defender connection filter policy Default."
            )
            assert result[0].resource == defender_client.connection_filter_policy.dict()
            assert result[0].resource_name == "Defender Connection Filter Policy"
            assert result[0].resource_id == "Default"
            assert result[0].location == "global"

    def test_safe_list_on(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off import (
                defender_antispam_connection_filter_policy_safe_list_off,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                ConnectionFilterPolicy,
            )

            defender_client.connection_filter_policy = ConnectionFilterPolicy(
                ip_allow_list=[],
                identity="Default",
                enable_safe_list=True,
            )

            check = defender_antispam_connection_filter_policy_safe_list_off()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Safe List is on in the Defender connection filter policy Default."
            )
            assert result[0].resource == defender_client.connection_filter_policy.dict()
            assert result[0].resource_name == "Defender Connection Filter Policy"
            assert result[0].resource_id == "Default"
            assert result[0].location == "global"

    def test_no_connection_filter_policy(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_connection_filter_policy_safe_list_off.defender_antispam_connection_filter_policy_safe_list_off import (
                defender_antispam_connection_filter_policy_safe_list_off,
            )

            defender_client.connection_filter_policy = None

            check = defender_antispam_connection_filter_policy_safe_list_off()
            result = check.execute()

            assert len(result) == 0
