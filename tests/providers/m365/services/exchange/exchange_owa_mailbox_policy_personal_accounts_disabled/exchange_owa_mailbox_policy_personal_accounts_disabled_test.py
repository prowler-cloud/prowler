from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_owa_mailbox_policy_personal_accounts_disabled:
    def test_exchange_no_mailbox_policies(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.mailbox_policies = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_exchange_non_default_policy_ignored(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            # A non-default policy that is non-compliant must be ignored.
            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Custom",
                    additional_storage_enabled=False,
                    is_default=False,
                    personal_accounts_enabled=True,
                    personal_account_calendars_enabled=True,
                )
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_exchange_default_policy_personal_accounts_disabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    additional_storage_enabled=False,
                    is_default=True,
                    personal_accounts_enabled=False,
                    personal_account_calendars_enabled=False,
                )
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default OWA mailbox policy 'OwaMailboxPolicy-Default' disables personal account integration."
            )
            assert result[0].resource == exchange_client.mailbox_policies[0].dict()
            assert (
                result[0].resource_name
                == "Exchange Mailbox Policy - OwaMailboxPolicy-Default"
            )
            assert result[0].resource_id == "OwaMailboxPolicy-Default"
            assert result[0].location == "global"

    def test_exchange_default_policy_personal_accounts_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    additional_storage_enabled=False,
                    is_default=True,
                    personal_accounts_enabled=True,
                    personal_account_calendars_enabled=True,
                )
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default OWA mailbox policy 'OwaMailboxPolicy-Default' allows personal accounts and personal account calendars."
            )
            assert result[0].resource == exchange_client.mailbox_policies[0].dict()
            assert (
                result[0].resource_name
                == "Exchange Mailbox Policy - OwaMailboxPolicy-Default"
            )
            assert result[0].resource_id == "OwaMailboxPolicy-Default"
            assert result[0].location == "global"

    def test_exchange_default_policy_only_personal_accounts_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    additional_storage_enabled=False,
                    is_default=True,
                    personal_accounts_enabled=True,
                    personal_account_calendars_enabled=False,
                )
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default OWA mailbox policy 'OwaMailboxPolicy-Default' allows personal accounts."
            )

    def test_exchange_default_policy_only_personal_calendars_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    additional_storage_enabled=False,
                    is_default=True,
                    personal_accounts_enabled=False,
                    personal_account_calendars_enabled=True,
                )
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default OWA mailbox policy 'OwaMailboxPolicy-Default' allows personal account calendars."
            )

    def test_exchange_default_and_custom_policies(self):
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
                "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                MailboxPolicy,
            )

            # Only the default policy must produce a finding.
            exchange_client.mailbox_policies = [
                MailboxPolicy(
                    id="OwaMailboxPolicy-Custom",
                    additional_storage_enabled=False,
                    is_default=False,
                    personal_accounts_enabled=True,
                    personal_account_calendars_enabled=True,
                ),
                MailboxPolicy(
                    id="OwaMailboxPolicy-Default",
                    additional_storage_enabled=False,
                    is_default=True,
                    personal_accounts_enabled=False,
                    personal_account_calendars_enabled=False,
                ),
            ]

            check = exchange_owa_mailbox_policy_personal_accounts_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "OwaMailboxPolicy-Default"
