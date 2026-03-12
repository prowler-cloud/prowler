from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_shared_mailbox_sign_in_disabled:
    def test_no_shared_mailboxes(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.shared_mailboxes = []

        entra_client = mock.MagicMock()
        entra_client.users = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled import (
                exchange_shared_mailbox_sign_in_disabled,
            )

            check = exchange_shared_mailbox_sign_in_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_sign_in_disabled(self):
        """PASS: Shared mailbox has sign-in blocked (AccountEnabled = False in Entra ID)."""
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
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service import User
            from prowler.providers.m365.services.exchange.exchange_service import (
                SharedMailbox,
            )
            from prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled import (
                exchange_shared_mailbox_sign_in_disabled,
            )

            shared_mailbox = SharedMailbox(
                name="Support Mailbox",
                user_principal_name="support@contoso.com",
                external_directory_object_id="12345678-1234-1234-1234-123456789012",
                identity="support@contoso.com",
            )
            exchange_client.shared_mailboxes = [shared_mailbox]

            entra_user = User(
                id="12345678-1234-1234-1234-123456789012",
                name="Support Mailbox",
                on_premises_sync_enabled=False,
                account_enabled=False,
            )
            entra_client = mock.MagicMock()
            entra_client.users = {
                "12345678-1234-1234-1234-123456789012": entra_user,
            }

            with mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.entra_client",
                new=entra_client,
            ):
                check = exchange_shared_mailbox_sign_in_disabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Shared mailbox support@contoso.com has sign-in blocked."
                )
                assert result[0].resource_name == "Support Mailbox"
                assert result[0].resource_id == "12345678-1234-1234-1234-123456789012"
                assert result[0].location == "global"

    def test_sign_in_enabled(self):
        """FAIL: Shared mailbox has sign-in enabled (AccountEnabled = True in Entra ID)."""
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
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service import User
            from prowler.providers.m365.services.exchange.exchange_service import (
                SharedMailbox,
            )
            from prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled import (
                exchange_shared_mailbox_sign_in_disabled,
            )

            shared_mailbox = SharedMailbox(
                name="Info Mailbox",
                user_principal_name="info@contoso.com",
                external_directory_object_id="87654321-4321-4321-4321-210987654321",
                identity="info@contoso.com",
            )
            exchange_client.shared_mailboxes = [shared_mailbox]

            entra_user = User(
                id="87654321-4321-4321-4321-210987654321",
                name="Info Mailbox",
                on_premises_sync_enabled=False,
                account_enabled=True,
            )
            entra_client = mock.MagicMock()
            entra_client.users = {
                "87654321-4321-4321-4321-210987654321": entra_user,
            }

            with mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.entra_client",
                new=entra_client,
            ):
                check = exchange_shared_mailbox_sign_in_disabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Shared mailbox info@contoso.com has sign-in enabled."
                )
                assert result[0].resource_name == "Info Mailbox"
                assert result[0].resource_id == "87654321-4321-4321-4321-210987654321"
                assert result[0].location == "global"

    def test_user_not_found_in_entra(self):
        """FAIL: Shared mailbox not found in Entra ID for verification."""
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
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_service import (
                SharedMailbox,
            )
            from prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled import (
                exchange_shared_mailbox_sign_in_disabled,
            )

            shared_mailbox = SharedMailbox(
                name="Orphan Mailbox",
                user_principal_name="orphan@contoso.com",
                external_directory_object_id="00000000-0000-0000-0000-000000000000",
                identity="orphan@contoso.com",
            )
            exchange_client.shared_mailboxes = [shared_mailbox]

            entra_client = mock.MagicMock()
            entra_client.users = {}

            with mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.entra_client",
                new=entra_client,
            ):
                check = exchange_shared_mailbox_sign_in_disabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Shared mailbox orphan@contoso.com could not be found in Entra ID for verification."
                )
                assert result[0].resource_name == "Orphan Mailbox"
                assert result[0].resource_id == "00000000-0000-0000-0000-000000000000"
                assert result[0].location == "global"

    def test_multiple_shared_mailboxes_mixed_status(self):
        """Test multiple shared mailboxes with different sign-in statuses."""
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
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service import User
            from prowler.providers.m365.services.exchange.exchange_service import (
                SharedMailbox,
            )
            from prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled import (
                exchange_shared_mailbox_sign_in_disabled,
            )

            mailbox_disabled = SharedMailbox(
                name="Secure Mailbox",
                user_principal_name="secure@contoso.com",
                external_directory_object_id="11111111-1111-1111-1111-111111111111",
                identity="secure@contoso.com",
            )
            mailbox_enabled = SharedMailbox(
                name="Insecure Mailbox",
                user_principal_name="insecure@contoso.com",
                external_directory_object_id="22222222-2222-2222-2222-222222222222",
                identity="insecure@contoso.com",
            )
            mailbox_orphan = SharedMailbox(
                name="Unknown Mailbox",
                user_principal_name="unknown@contoso.com",
                external_directory_object_id="33333333-3333-3333-3333-333333333333",
                identity="unknown@contoso.com",
            )

            exchange_client.shared_mailboxes = [
                mailbox_disabled,
                mailbox_enabled,
                mailbox_orphan,
            ]

            user_disabled = User(
                id="11111111-1111-1111-1111-111111111111",
                name="Secure Mailbox",
                on_premises_sync_enabled=False,
                account_enabled=False,
            )
            user_enabled = User(
                id="22222222-2222-2222-2222-222222222222",
                name="Insecure Mailbox",
                on_premises_sync_enabled=False,
                account_enabled=True,
            )

            entra_client = mock.MagicMock()
            entra_client.users = {
                "11111111-1111-1111-1111-111111111111": user_disabled,
                "22222222-2222-2222-2222-222222222222": user_enabled,
            }

            with mock.patch(
                "prowler.providers.m365.services.exchange.exchange_shared_mailbox_sign_in_disabled.exchange_shared_mailbox_sign_in_disabled.entra_client",
                new=entra_client,
            ):
                check = exchange_shared_mailbox_sign_in_disabled()
                result = check.execute()

                assert len(result) == 3

                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Shared mailbox secure@contoso.com has sign-in blocked."
                )

                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == "Shared mailbox insecure@contoso.com has sign-in enabled."
                )

                assert result[2].status == "FAIL"
                assert (
                    result[2].status_extended
                    == "Shared mailbox unknown@contoso.com could not be found in Entra ID for verification."
                )
