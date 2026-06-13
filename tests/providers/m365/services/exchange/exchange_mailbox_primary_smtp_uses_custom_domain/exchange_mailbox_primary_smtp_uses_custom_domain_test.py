from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_mailbox_primary_smtp_uses_custom_domain:

    def test_powershell_unavailable_manual(self):
        """MANUAL: Exchange Online PowerShell unavailable (mailboxes is None)."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.mailboxes = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "PowerShell" in result[0].status_extended
            assert result[0].resource_name == "Exchange Online Mailboxes"
            assert result[0].resource_id == "exchange_mailboxes"

    def test_empty_tenant_no_findings(self):
        """Empty tenant (no mailboxes) produces zero findings, not MANUAL."""
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.mailboxes = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert result == []

    def test_custom_domain_passes(self):
        """PASS: Mailbox primary SMTP uses a custom domain."""
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Mailbox,
            )

            exchange_client.mailboxes = [
                Mailbox(
                    identity="user1@contoso.com",
                    name="User One",
                    primary_smtp_address="user1@contoso.com",
                    recipient_type_details="UserMailbox",
                )
            ]

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "custom domain" in result[0].status_extended
            assert result[0].resource_name == "User One"
            assert result[0].resource_id == "user1@contoso.com"
            assert result[0].location == "global"

    def test_onmicrosoft_domain_fails(self):
        """FAIL: Mailbox primary SMTP uses .onmicrosoft.com."""
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Mailbox,
            )

            exchange_client.mailboxes = [
                Mailbox(
                    identity="user1@contoso.onmicrosoft.com",
                    name="User One",
                    primary_smtp_address="user1@contoso.onmicrosoft.com",
                    recipient_type_details="UserMailbox",
                )
            ]

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert ".onmicrosoft.com" in result[0].status_extended
            assert result[0].resource_name == "User One"
            assert result[0].resource_id == "user1@contoso.onmicrosoft.com"
            assert result[0].location == "global"

    def test_mixed_mailboxes(self):
        """Test multiple mailboxes with mixed domain status."""
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Mailbox,
            )

            exchange_client.mailboxes = [
                Mailbox(
                    identity="user1@contoso.com",
                    name="User One",
                    primary_smtp_address="user1@contoso.com",
                    recipient_type_details="UserMailbox",
                ),
                Mailbox(
                    identity="shared@contoso.onmicrosoft.com",
                    name="Shared Mailbox",
                    primary_smtp_address="shared@contoso.onmicrosoft.com",
                    recipient_type_details="SharedMailbox",
                ),
            ]

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Mailbox user1@contoso.com (UserMailbox) has primary SMTP address user1@contoso.com using a custom domain."
            )
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Mailbox shared@contoso.onmicrosoft.com (SharedMailbox) has primary SMTP address shared@contoso.onmicrosoft.com using the .onmicrosoft.com domain instead of a custom domain."
            )

    def test_room_mailbox_custom_domain(self):
        """PASS: Room mailbox using a custom domain."""
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Mailbox,
            )

            exchange_client.mailboxes = [
                Mailbox(
                    identity="boardroom@contoso.com",
                    name="Board Room",
                    primary_smtp_address="boardroom@contoso.com",
                    recipient_type_details="RoomMailbox",
                )
            ]

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "boardroom@contoso.com"
            assert result[0].location == "global"

    def test_equipment_mailbox_onmicrosoft(self):
        """FAIL: Equipment mailbox using .onmicrosoft.com."""
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
                "prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_mailbox_primary_smtp_uses_custom_domain.exchange_mailbox_primary_smtp_uses_custom_domain import (
                exchange_mailbox_primary_smtp_uses_custom_domain,
            )
            from prowler.providers.m365.services.exchange.exchange_service import (
                Mailbox,
            )

            exchange_client.mailboxes = [
                Mailbox(
                    identity="projector@contoso.onmicrosoft.com",
                    name="Projector",
                    primary_smtp_address="projector@contoso.onmicrosoft.com",
                    recipient_type_details="EquipmentMailbox",
                )
            ]

            check = exchange_mailbox_primary_smtp_uses_custom_domain()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "projector@contoso.onmicrosoft.com"
            assert result[0].location == "global"
