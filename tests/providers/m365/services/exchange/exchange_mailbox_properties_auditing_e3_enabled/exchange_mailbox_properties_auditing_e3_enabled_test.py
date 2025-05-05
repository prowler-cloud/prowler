from unittest import mock

from prowler.providers.m365.services.exchange.exchange_service import (
    AuditAdmin,
    AuditDelegate,
    AuditOwner,
    MailboxAuditProperties,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_mailbox_properties_auditing_e3_enabled:
    def test_no_auditing_mailboxes(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled import (
                exchange_mailbox_properties_auditing_e3_enabled,
            )

            exchange_client.mailbox_audit_properties = []

            check = exchange_mailbox_properties_auditing_e3_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_auditing_fully_configured_and_log_age_valid(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled import (
                exchange_mailbox_properties_auditing_e3_enabled,
            )

            exchange_client.mailbox_audit_properties = [
                MailboxAuditProperties(
                    name="User1",
                    audit_enabled=True,
                    audit_admin=[e.value for e in AuditAdmin],
                    audit_delegate=[e.value for e in AuditDelegate],
                    audit_owner=[e.value for e in AuditOwner],
                    audit_log_age=180,
                    identity="User1",
                )
            ]

            check = exchange_mailbox_properties_auditing_e3_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Mailbox Audit Properties for Mailbox User1 is enabled and properly configured."
            )
            assert result[0].resource_name == "User1"
            assert result[0].resource_id == "User1"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.mailbox_audit_properties[0].dict()
            )

    def test_audit_enabled_but_incomplete_configuration(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled import (
                exchange_mailbox_properties_auditing_e3_enabled,
            )

            exchange_client.mailbox_audit_properties = [
                MailboxAuditProperties(
                    name="User2",
                    audit_enabled=True,
                    audit_admin=["SendAs"],
                    audit_delegate=["Send"],
                    audit_owner=["Update"],
                    audit_log_age=180,
                    identity="User2",
                )
            ]

            check = exchange_mailbox_properties_auditing_e3_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Mailbox Audit Properties for Mailbox User2 is enabled but not properly configured. Missing audit actions may exist."
            )
            assert result[0].resource_name == "User2"
            assert result[0].resource_id == "User2"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.mailbox_audit_properties[0].dict()
            )

    def test_audit_not_enabled(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled import (
                exchange_mailbox_properties_auditing_e3_enabled,
            )

            exchange_client.mailbox_audit_properties = [
                MailboxAuditProperties(
                    name="User3",
                    audit_enabled=False,
                    audit_admin=[],
                    audit_delegate=[],
                    audit_owner=[],
                    audit_log_age=0,
                    identity="User3",
                )
            ]

            check = exchange_mailbox_properties_auditing_e3_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Mailbox Audit Properties for Mailbox User3 is not enabled."
            )
            assert result[0].resource_name == "User3"
            assert result[0].resource_id == "User3"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.mailbox_audit_properties[0].dict()
            )

    def test_audit_enabled_but_log_age_too_low(self):
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_properties_auditing_e3_enabled.exchange_mailbox_properties_auditing_e3_enabled import (
                exchange_mailbox_properties_auditing_e3_enabled,
            )

            exchange_client.mailbox_audit_properties = [
                MailboxAuditProperties(
                    name="User4",
                    audit_enabled=True,
                    audit_admin=[e.value for e in AuditAdmin],
                    audit_delegate=[e.value for e in AuditDelegate],
                    audit_owner=[e.value for e in AuditOwner],
                    audit_log_age=30,
                    identity="User4",
                )
            ]

            check = exchange_mailbox_properties_auditing_e3_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Mailbox Audit Properties for Mailbox User4 is enabled and properly configured but the audit log age is less than 90 days."
            )
            assert result[0].resource_name == "User4"
            assert result[0].resource_id == "User4"
            assert result[0].location == "global"
            assert (
                result[0].resource == exchange_client.mailbox_audit_properties[0].dict()
            )
