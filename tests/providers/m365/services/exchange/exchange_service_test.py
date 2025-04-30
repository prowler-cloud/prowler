from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.exchange.exchange_service import (
    Exchange,
    ExternalMailConfig,
    MailboxAuditConfig,
    MailboxAuditProperties,
    MailboxPolicy,
    Organization,
    TransportRule,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_exchange_get_organization_config(_):
    return Organization(audit_disabled=True, name="test", guid="test")


def mock_exchange_get_mailbox_audit_config(_):
    return [
        MailboxAuditConfig(name="test", id="test", audit_bypass_enabled=False),
        MailboxAuditConfig(name="test2", id="test2", audit_bypass_enabled=True),
    ]


def mock_exchange_get_external_mail_config(_):
    return [
        ExternalMailConfig(
            identity="test",
            external_mail_tag_enabled=True,
        ),
        ExternalMailConfig(
            identity="test2",
            external_mail_tag_enabled=False,
        ),
    ]


def mock_exchange_get_transport_rules(_):
    return [
        TransportRule(
            name="test",
            scl=-1,
            sender_domain_is=["example.com"],
        ),
        TransportRule(
            name="test2",
            scl=0,
            sender_domain_is=["example.com"],
        ),
    ]


def mock_exchange_get_mailbox_policy(_):
    return MailboxPolicy(
        id="test",
        additional_storage_enabled=True,
    )


def mock_exchange_get_mailbox_audit_properties(_):
    return [
        MailboxAuditProperties(
            name="User1",
            audit_enabled=False,
            audit_admin=[
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "SendAs",
                "SendOnBehalf",
                "Create",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "UpdateCalendarDelegation",
                "ApplyRecord",
                "MailItemsAccessed",
                "Send",
            ],
            audit_delegate=[
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "SendAs",
                "SendOnBehalf",
                "Create",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "ApplyRecord",
                "MailItemsAccessed",
            ],
            audit_owner=[
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "UpdateCalendarDelegation",
                "ApplyRecord",
                "MailItemsAccessed",
                "Send",
            ],
            audit_log_age=90,
            identity="test",
        )
    ]


class Test_Exchange_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert exchange_client.client.__class__.__name__ == "GraphServiceClient"
            assert exchange_client.powershell.__class__.__name__ == "M365PowerShell"
            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_organization_config",
        new=mock_exchange_get_organization_config,
    )
    def test_get_organization_config(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            organization_config = exchange_client.organization_config
            assert organization_config.name == "test"
            assert organization_config.guid == "test"
            assert organization_config.audit_disabled is True

            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_mailbox_audit_config",
        new=mock_exchange_get_mailbox_audit_config,
    )
    def test_get_mailbox_audit_config(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            mailbox_audit_config = exchange_client.mailboxes_config
            assert len(mailbox_audit_config) == 2
            assert mailbox_audit_config[0].name == "test"
            assert mailbox_audit_config[0].id == "test"
            assert mailbox_audit_config[0].audit_bypass_enabled is False
            assert mailbox_audit_config[1].name == "test2"
            assert mailbox_audit_config[1].id == "test2"
            assert mailbox_audit_config[1].audit_bypass_enabled is True

            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_external_mail_config",
        new=mock_exchange_get_external_mail_config,
    )
    def test_get_external_mail_config(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            external_mail_config = exchange_client.external_mail_config
            assert len(external_mail_config) == 2
            assert external_mail_config[0].identity == "test"
            assert external_mail_config[0].external_mail_tag_enabled is True
            assert external_mail_config[1].identity == "test2"
            assert external_mail_config[1].external_mail_tag_enabled is False
            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_transport_rules",
        new=mock_exchange_get_transport_rules,
    )
    def test_get_transport_rules(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            transport_rules = exchange_client.transport_rules
            assert len(transport_rules) == 2
            assert transport_rules[0].name == "test"
            assert transport_rules[0].scl == -1
            assert transport_rules[0].sender_domain_is == ["example.com"]
            assert transport_rules[1].name == "test2"
            assert transport_rules[1].scl == 0
            assert transport_rules[1].sender_domain_is == ["example.com"]

            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_mailbox_policy",
        new=mock_exchange_get_mailbox_policy,
    )
    def test_get_mailbox_policy(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy.id == "test"
            assert mailbox_policy.additional_storage_enabled is True
            exchange_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_mailbox_audit_properties",
        new=mock_exchange_get_mailbox_audit_properties,
    )
    def test_get_mailbox_audit_properties(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            mailbox_audit_properties = exchange_client.mailbox_audit_properties
            assert len(mailbox_audit_properties) == 1
            assert mailbox_audit_properties[0].name == "User1"
            assert mailbox_audit_properties[0].audit_enabled is False
            assert mailbox_audit_properties[0].audit_admin == [
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "SendAs",
                "SendOnBehalf",
                "Create",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "UpdateCalendarDelegation",
                "ApplyRecord",
                "MailItemsAccessed",
                "Send",
            ]
            assert mailbox_audit_properties[0].audit_delegate == [
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "SendAs",
                "SendOnBehalf",
                "Create",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "ApplyRecord",
                "MailItemsAccessed",
            ]
            assert mailbox_audit_properties[0].audit_owner == [
                "Update",
                "MoveToDeletedItems",
                "SoftDelete",
                "HardDelete",
                "UpdateFolderPermissions",
                "UpdateInboxRules",
                "UpdateCalendarDelegation",
                "ApplyRecord",
                "MailItemsAccessed",
                "Send",
            ]
            assert mailbox_audit_properties[0].audit_log_age == 90
            assert mailbox_audit_properties[0].identity == "test"
            exchange_client.powershell.close()
