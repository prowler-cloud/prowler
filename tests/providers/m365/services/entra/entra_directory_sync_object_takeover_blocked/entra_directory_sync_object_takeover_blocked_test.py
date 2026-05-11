from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DirectorySyncSettings,
    Organization,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_directory_sync_object_takeover_blocked:
    def test_both_blocks_enabled(self):
        """PASS when both soft-match and hard-match blocks are enabled."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    block_soft_match_enabled=True,
                    block_cloud_object_takeover_through_hard_match_enabled=True,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "blocks both soft-match and hard-match" in result[0].status_extended

    def test_soft_match_disabled(self):
        """FAIL when soft-match block is disabled."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    block_soft_match_enabled=False,
                    block_cloud_object_takeover_through_hard_match_enabled=True,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "blockSoftMatchEnabled" in result[0].status_extended

    def test_hard_match_disabled(self):
        """FAIL when hard-match block is disabled."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    block_soft_match_enabled=True,
                    block_cloud_object_takeover_through_hard_match_enabled=False,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "blockCloudObjectTakeoverThroughHardMatchEnabled" in result[0].status_extended

    def test_both_blocks_disabled(self):
        """FAIL when both blocks are disabled."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    block_soft_match_enabled=False,
                    block_cloud_object_takeover_through_hard_match_enabled=False,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "blockSoftMatchEnabled" in result[0].status_extended
            assert "blockCloudObjectTakeoverThroughHardMatchEnabled" in result[0].status_extended

    def test_cloud_only_tenant(self):
        """PASS when tenant is cloud-only (no directory sync)."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = None
            entra_client.organizations = [
                Organization(
                    id="org-001",
                    name="Cloud Only Org",
                    on_premises_sync_enabled=False,
                )
            ]

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "cloud-only" in result[0].status_extended

    def test_permission_error_hybrid(self):
        """FAIL when permissions are insufficient for a hybrid tenant."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_takeover_blocked.entra_directory_sync_object_takeover_blocked import (
                entra_directory_sync_object_takeover_blocked,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = "Insufficient privileges"
            entra_client.organizations = [
                Organization(
                    id="org-001",
                    name="Hybrid Org",
                    on_premises_sync_enabled=True,
                )
            ]

            check = entra_directory_sync_object_takeover_blocked()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Cannot verify" in result[0].status_extended
