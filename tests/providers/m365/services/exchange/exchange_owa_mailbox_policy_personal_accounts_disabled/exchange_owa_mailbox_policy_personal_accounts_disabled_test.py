from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled"


def _make_policy(
    policy_id,
    is_default=True,
    personal_accounts_enabled=True,
    personal_account_calendars_enabled=True,
):
    from prowler.providers.m365.services.exchange.exchange_service import MailboxPolicy

    return MailboxPolicy(
        id=policy_id,
        additional_storage_enabled=False,
        is_default=is_default,
        personal_accounts_enabled=personal_accounts_enabled,
        personal_account_calendars_enabled=personal_account_calendars_enabled,
    )


class Test_exchange_owa_mailbox_policy_personal_accounts_disabled:
    def _run(self, policies):
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
            from prowler.providers.m365.services.exchange.exchange_owa_mailbox_policy_personal_accounts_disabled.exchange_owa_mailbox_policy_personal_accounts_disabled import (
                exchange_owa_mailbox_policy_personal_accounts_disabled,
            )

            exchange_client.mailbox_policies = policies
            return exchange_owa_mailbox_policy_personal_accounts_disabled().execute()

    def test_no_policies(self):
        assert self._run([]) == []

    def test_only_non_default_policies_ignored(self):
        # A non-default policy that is non-compliant must be ignored.
        result = self._run([_make_policy("OwaMailboxPolicy-Custom", is_default=False)])
        assert result == []

    def test_default_policy_disabled(self):
        result = self._run(
            [
                _make_policy(
                    "OwaMailboxPolicy-Default",
                    personal_accounts_enabled=False,
                    personal_account_calendars_enabled=False,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_default_policy_enabled(self):
        result = self._run([_make_policy("OwaMailboxPolicy-Default")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
