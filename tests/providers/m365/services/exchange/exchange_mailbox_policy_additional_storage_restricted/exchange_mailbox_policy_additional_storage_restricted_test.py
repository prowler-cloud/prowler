from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_mailbox_policy_additional_storage_restricted:
    def test_mailbox_policy_restricts_additional_storage(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted import (
                exchange_mailbox_policy_additional_storage_restricted,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policy = MailboxPolicy(
                id="OwaMailboxPolicy-Default", additional_storage_enabled=False
            )

            check = exchange_mailbox_policy_additional_storage_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Exchange mailbox policy restricts additional storage providers."
            )
            assert result[0].resource == exchange_client.mailbox_policy.dict()
            assert result[0].resource_name == "Exchange Mailbox Policy"
            assert result[0].resource_id == "OwaMailboxPolicy-Default"
            assert result[0].location == "global"

    def test_mailbox_policy_allows_additional_storage(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted import (
                exchange_mailbox_policy_additional_storage_restricted,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policy = MailboxPolicy(
                id="OwaMailboxPolicy-Default", additional_storage_enabled=True
            )

            check = exchange_mailbox_policy_additional_storage_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Exchange mailbox policy allows additional storage providers."
            )
            assert result[0].resource == exchange_client.mailbox_policy.dict()
            assert result[0].resource_name == "Exchange Mailbox Policy"
            assert result[0].resource_id == "OwaMailboxPolicy-Default"
            assert result[0].location == "global"

    def test_no_mailbox_policy(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.mailbox_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_policy_additional_storage_restricted.exchange_mailbox_policy_additional_storage_restricted import (
                exchange_mailbox_policy_additional_storage_restricted,
            )

            check = exchange_mailbox_policy_additional_storage_restricted()
            result = check.execute()
            assert len(result) == 0
