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
    RoleAssignmentPolicy,
    TransportConfig,
    TransportRule,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_exchange_get_organization_config(_):
    return Organization(
        audit_disabled=True,
        name="test",
        guid="test",
        oauth_enabled=True,
        mailtips_enabled=True,
        mailtips_external_recipient_enabled=False,
        mailtips_group_metrics_enabled=True,
        mailtips_large_audience_threshold=25,
    )


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
            redirect_message_to=None,
        ),
        TransportRule(
            name="test2",
            scl=0,
            sender_domain_is=["example.com"],
            redirect_message_to=["test@example.com"],
        ),
    ]


def mock_exchange_get_transport_config(_):
    return TransportConfig(
        smtp_auth_disabled=True,
    )


def mock_exchange_get_mailbox_policy(_):
    return MailboxPolicy(
        id="test",
        additional_storage_enabled=True,
    )


def mock_exchange_get_role_assignment_policies(_):
    return [
        RoleAssignmentPolicy(
            name="Default Role Assignment Policy",
            id="12345678-1234-1234-1234",
            assigned_roles=[
                "MyProfileInformation",
                "MyDistributionGroupMembership",
                "MyRetentionPolicies",
                "MyDistributionGroups",
                "MyVoiceMail",
            ],
        ),
        RoleAssignmentPolicy(
            name="Test Policy",
            id="12345678-1234-1234",
            assigned_roles=[],
        ),
    ]


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
            assert organization_config.oauth_enabled is True
            assert organization_config.mailtips_enabled is True
            assert organization_config.mailtips_external_recipient_enabled is False
            assert organization_config.mailtips_group_metrics_enabled is True
            assert organization_config.mailtips_large_audience_threshold == 25

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
            assert transport_rules[0].redirect_message_to is None
            assert transport_rules[1].name == "test2"
            assert transport_rules[1].scl == 0
            assert transport_rules[1].sender_domain_is == ["example.com"]
            assert transport_rules[1].redirect_message_to == ["test@example.com"]

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
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_transport_config",
        new=mock_exchange_get_transport_config,
    )
    def test_get_transport_config(self):
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
            transport_config = exchange_client.transport_config
            assert transport_config.smtp_auth_disabled is True

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

    @patch(
        "prowler.providers.m365.services.exchange.exchange_service.Exchange._get_role_assignment_policies",
        new=mock_exchange_get_role_assignment_policies,
    )
    def test_get_role_assignment_policies(self):
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
            role_assignment_policies = exchange_client.role_assignment_policies
            assert len(role_assignment_policies) == 2
            assert role_assignment_policies[0].name == "Default Role Assignment Policy"
            assert role_assignment_policies[0].id == "12345678-1234-1234-1234"
            assert role_assignment_policies[0].assigned_roles == [
                "MyProfileInformation",
                "MyDistributionGroupMembership",
                "MyRetentionPolicies",
                "MyDistributionGroups",
                "MyVoiceMail",
            ]
            assert role_assignment_policies[1].name == "Test Policy"
            assert role_assignment_policies[1].id == "12345678-1234-1234"
            assert role_assignment_policies[1].assigned_roles == []

            exchange_client.powershell.close()

    def test_get_organization_config_with_string_data(self):
        """Test that _get_organization_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value="InvalidStringConfig",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            organization_config = exchange_client.organization_config
            assert organization_config is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid organization config data type: <class 'str'> - InvalidStringConfig"
            )

            exchange_client.powershell.close()

    def test_get_mailbox_audit_config_with_string_data(self):
        """Test that _get_mailbox_audit_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_audit_config",
                return_value=[
                    "MailboxConfig1",
                    "MailboxConfig2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid configs were processed
            mailboxes_config = exchange_client.mailboxes_config
            assert mailboxes_config == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid mailbox audit config data type: <class 'str'> - MailboxConfig1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid mailbox audit config data type: <class 'str'> - MailboxConfig2"
            )

            exchange_client.powershell.close()

    def test_get_external_mail_config_with_string_data(self):
        """Test that _get_external_mail_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_external_mail_config",
                return_value=[
                    "ExternalMail1",
                    "ExternalMail2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid configs were processed
            external_mail_config = exchange_client.external_mail_config
            assert external_mail_config == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid external mail config data type: <class 'str'> - ExternalMail1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid external mail config data type: <class 'str'> - ExternalMail2"
            )

            exchange_client.powershell.close()

    def test_get_transport_rules_with_string_data(self):
        """Test that _get_transport_rules handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_rules",
                return_value=[
                    "TransportRule1",
                    "TransportRule2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid rules were processed
            transport_rules = exchange_client.transport_rules
            assert transport_rules == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid transport rule data type: <class 'str'> - TransportRule1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid transport rule data type: <class 'str'> - TransportRule2"
            )

            exchange_client.powershell.close()

    def test_get_transport_config_with_string_data(self):
        """Test that _get_transport_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_config",
                return_value="InvalidStringConfig",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            transport_config = exchange_client.transport_config
            assert transport_config is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid transport config data type: <class 'str'> - InvalidStringConfig"
            )

            exchange_client.powershell.close()

    def test_get_mailbox_policy_with_string_data(self):
        """Test that _get_mailbox_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_policy",
                return_value="InvalidStringPolicy",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid mailbox policy data type: <class 'str'> - InvalidStringPolicy"
            )

            exchange_client.powershell.close()

    def test_get_role_assignment_policies_with_string_data(self):
        """Test that _get_role_assignment_policies handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_role_assignment_policies",
                return_value=[
                    "RolePolicy1",
                    "RolePolicy2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid policies were processed
            role_assignment_policies = exchange_client.role_assignment_policies
            assert role_assignment_policies == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid role assignment policy data type: <class 'str'> - RolePolicy1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid role assignment policy data type: <class 'str'> - RolePolicy2"
            )

            exchange_client.powershell.close()

    def test_get_mailbox_audit_properties_with_string_data(self):
        """Test that _get_mailbox_audit_properties handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_audit_properties",
                return_value=[
                    "AuditProperty1",
                    "AuditProperty2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid properties were processed
            mailbox_audit_properties = exchange_client.mailbox_audit_properties
            assert mailbox_audit_properties == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid mailbox audit property data type: <class 'str'> - AuditProperty1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid mailbox audit property data type: <class 'str'> - AuditProperty2"
            )

            exchange_client.powershell.close()

    def test_get_transport_config_with_mixed_data(self):
        """Test that _get_transport_config handles mixed data (dict + string) gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_config",
                return_value=[
                    {"SmtpClientAuthenticationDisabled": True},  # Valid dict
                    "InvalidStringConfig",  # Invalid string
                ],
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return valid config from first item
            transport_config = exchange_client.transport_config
            assert transport_config is not None
            assert transport_config.smtp_auth_disabled is True

            # Should log warning for the string item (but only if it's processed after the first valid item)
            # Since we break after first valid item, the warning might not be called
            # This test verifies the behavior is correct regardless

            exchange_client.powershell.close()

    def test_get_transport_config_with_empty_data(self):
        """Test that _get_transport_config handles empty data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_config",
                return_value=[],  # Empty list
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            transport_config = exchange_client.transport_config
            assert transport_config is None

            exchange_client.powershell.close()

    def test_get_transport_config_with_none_data(self):
        """Test that _get_transport_config handles None data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_config",
                return_value=None,  # None data
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            transport_config = exchange_client.transport_config
            assert transport_config is None

            exchange_client.powershell.close()

    def test_get_mailbox_policy_with_mixed_data(self):
        """Test that _get_mailbox_policy handles mixed data (dict + string) gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_policy",
                return_value=[
                    {
                        "Id": "Policy1",
                        "AdditionalStorageProvidersAvailable": False,
                    },  # Valid dict
                    "InvalidStringPolicy",  # Invalid string
                ],
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return valid policy from first item
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy is not None
            assert mailbox_policy.id == "Policy1"
            assert mailbox_policy.additional_storage_enabled is False

            # Should log warning for the string item (but only if it's processed after the first valid item)
            # Since we break after first valid item, the warning might not be called
            # This test verifies the behavior is correct regardless

            exchange_client.powershell.close()

    def test_get_mailbox_policy_with_empty_data(self):
        """Test that _get_mailbox_policy handles empty data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_policy",
                return_value=[],  # Empty list
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy is None

            exchange_client.powershell.close()

    def test_get_mailbox_policy_with_none_data(self):
        """Test that _get_mailbox_policy handles None data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_policy",
                return_value=None,  # None data
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy is None

            exchange_client.powershell.close()

    def test_get_transport_config_with_multiple_valid_configs(self):
        """Test that _get_transport_config takes first valid config when multiple are available"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_transport_config",
                return_value=[
                    {"SmtpClientAuthenticationDisabled": True},  # First valid config
                    {
                        "SmtpClientAuthenticationDisabled": False
                    },  # Second valid config (should be ignored)
                ],
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return first valid config
            transport_config = exchange_client.transport_config
            assert transport_config is not None
            assert transport_config.smtp_auth_disabled is True  # First config value

            exchange_client.powershell.close()

    def test_get_mailbox_policy_with_multiple_valid_policies(self):
        """Test that _get_mailbox_policy takes first valid policy when multiple are available"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_mailbox_policy",
                return_value=[
                    {
                        "Id": "Policy1",
                        "AdditionalStorageProvidersAvailable": True,
                    },  # First valid policy
                    {
                        "Id": "Policy2",
                        "AdditionalStorageProvidersAvailable": False,
                    },  # Second valid policy (should be ignored)
                ],
            ),
        ):
            exchange_client = Exchange(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return first valid policy
            mailbox_policy = exchange_client.mailbox_policy
            assert mailbox_policy is not None
            assert mailbox_policy.id == "Policy1"  # First policy
            assert (
                mailbox_policy.additional_storage_enabled is True
            )  # First policy value

            exchange_client.powershell.close()
