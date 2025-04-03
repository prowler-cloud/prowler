from unittest import mock

from prowler.providers.microsoft365.services.exchange.exchange_service import (
    MailboxAuditConfig,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_exchange_account_mailbox_audit_bypass_disabled:
    def test_no_mailboxes(self):
        exchange_client = mock.MagicMock
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.mailboxes_config = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled import (
                exchange_account_mailbox_audit_bypass_disabled,
            )

            check = exchange_account_mailbox_audit_bypass_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_audit_bypass_disabled_and_enabled(self):
        exchange_client = mock.MagicMock
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled import (
                exchange_account_mailbox_audit_bypass_disabled,
            )

            exchange_client = mock.MagicMock
            exchange_client.mailboxes_config = [
                MailboxAuditConfig(name="test", id="test", audit_bypass_enabled=True),
                MailboxAuditConfig(
                    name="test2", id="test2", audit_bypass_enabled=False
                ),
            ]

            check = exchange_account_mailbox_audit_bypass_disabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Exchange mailbox auditing is bypassed and not enabled for mailbox: test."
            )
            assert result[0].resource == exchange_client.mailboxes_config[0].dict()
            assert result[0].resource_name == "test"
            assert result[0].resource_id == "test"
            assert result[0].location == "global"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Exchange mailbox auditing is enabled for mailbox: test2."
            )
            assert result[1].resource == exchange_client.mailboxes_config[1].dict()
            assert result[1].resource_name == "test2"
            assert result[1].resource_id == "test2"
            assert result[1].location == "global"

    def test_audit_bypass_enabled(self):
        exchange_client = mock.MagicMock
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled import (
                exchange_account_mailbox_audit_bypass_disabled,
            )

            exchange_client = mock.MagicMock
            exchange_client.mailboxes_config = [
                MailboxAuditConfig(name="test", id="test", audit_bypass_enabled=True),
            ]

            check = exchange_account_mailbox_audit_bypass_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Exchange mailbox auditing is bypassed and not enabled for mailbox: test."
            )
            assert result[0].resource == exchange_client.mailboxes_config[0].dict()
            assert result[0].resource_name == "test"
            assert result[0].resource_id == "test"
            assert result[0].location == "global"

    def test_audit_bypass_disabled(self):
        exchange_client = mock.MagicMock
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.microsoft365.services.exchange.exchange_account_mailbox_audit_bypass_disabled.exchange_account_mailbox_audit_bypass_disabled import (
                exchange_account_mailbox_audit_bypass_disabled,
            )

            exchange_client = mock.MagicMock
            exchange_client.mailboxes_config = [
                MailboxAuditConfig(name="test", id="test", audit_bypass_enabled=False),
            ]

            check = exchange_account_mailbox_audit_bypass_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Exchange mailbox auditing is enabled for mailbox: test."
            )
            assert result[0].resource == exchange_client.mailboxes_config[0].dict()
            assert result[0].resource_name == "test"
            assert result[0].resource_id == "test"
            assert result[0].location == "global"
