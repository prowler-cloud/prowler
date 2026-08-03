from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_admincenter_shared_bookings_disabled:
    def test_admincenter_no_org_config(self):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN
        admincenter_client.organization_config = None
        admincenter_client.mailbox_policies = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_bookings_enabled_tenant_and_policy(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
                OwaMailboxPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
                bookings_enabled=True,
            )
            admincenter_client.mailbox_policies = [
                OwaMailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    is_default=True,
                    bookings_mailbox_creation_enabled=True,
                )
            ]

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Shared Bookings is enabled at the tenant level and the default OWA mailbox policy allows Bookings mailbox creation."
            )
            assert result[0].resource == admincenter_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_admincenter_bookings_enabled_no_default_policy(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
            )
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
                bookings_enabled=True,
            )
            admincenter_client.mailbox_policies = []

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Shared Bookings is enabled at the tenant level and no default OWA mailbox policy was found."
            )

    def test_admincenter_bookings_enabled_non_default_policy_disabled(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
                OwaMailboxPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
                bookings_enabled=True,
            )
            admincenter_client.mailbox_policies = [
                OwaMailboxPolicy(
                    id="OwaMailboxPolicy-Custom",
                    is_default=False,
                    bookings_mailbox_creation_enabled=False,
                )
            ]

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Shared Bookings is enabled at the tenant level and no default OWA mailbox policy was found."
            )

    def test_admincenter_bookings_disabled_at_tenant(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
                OwaMailboxPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
                bookings_enabled=False,
            )
            admincenter_client.mailbox_policies = [
                OwaMailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    is_default=True,
                    bookings_mailbox_creation_enabled=True,
                )
            ]

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Shared Bookings is disabled at the tenant level."
            )
            assert result[0].resource == admincenter_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"

    def test_admincenter_bookings_disabled_in_default_policy(self):
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
                "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                Organization,
                OwaMailboxPolicy,
            )
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = Organization(
                name="test-org",
                guid="org-guid",
                customer_lockbox_enabled=False,
                bookings_enabled=True,
            )
            admincenter_client.mailbox_policies = [
                OwaMailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    is_default=True,
                    bookings_mailbox_creation_enabled=False,
                )
            ]

            check = admincenter_shared_bookings_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Shared Bookings is disabled in the default OWA mailbox policy."
            )
            assert result[0].resource == admincenter_client.organization_config.dict()
            assert result[0].resource_name == "test-org"
            assert result[0].resource_id == "org-guid"
            assert result[0].location == "global"
