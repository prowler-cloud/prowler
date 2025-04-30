from unittest import mock

from prowler.providers.m365.services.exchange.exchange_service import (
    RoleAssignmentPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_roles_assignment_policy_addins_disabled:
    def test_no_policies(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online",
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled import (
                exchange_roles_assignment_policy_addins_disabled,
            )

            exchange_client.role_assignment_policies = []

            check = exchange_roles_assignment_policy_addins_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_policy_with_no_addin_roles(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online",
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled import (
                exchange_roles_assignment_policy_addins_disabled,
            )

            exchange_client.role_assignment_policies = [
                RoleAssignmentPolicy(
                    name="Policy1",
                    id="id-policy1",
                    assigned_roles=["MyBaseOptions", "MyVoiceMail"],
                )
            ]

            check = exchange_roles_assignment_policy_addins_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Role assignment policy 'Policy1' does not allow Outlook add-ins."
            )
            assert result[0].resource_name == "Policy1"
            assert result[0].resource_id == "id-policy1"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.role_assignment_policies[0].dict()
            )

    def test_policy_with_addin_roles(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online",
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_roles_assignment_policy_addins_disabled.exchange_roles_assignment_policy_addins_disabled import (
                exchange_roles_assignment_policy_addins_disabled,
            )

            exchange_client.role_assignment_policies = [
                RoleAssignmentPolicy(
                    name="Policy2",
                    id="id-policy2",
                    assigned_roles=["MyCustomApps", "MyVoiceMail"],
                )
            ]

            check = exchange_roles_assignment_policy_addins_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Role assignment policy 'Policy2' allows Outlook add-ins via roles: MyCustomApps."
            )
            assert result[0].resource_name == "Policy2"
            assert result[0].resource_id == "id-policy2"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.role_assignment_policies[0].dict()
            )
