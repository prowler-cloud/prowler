from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DirectorySyncSettings,
    Organization,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_seamless_sso_disabled:
    def test_seamless_sso_disabled(self):
        """Test PASS when Seamless SSO is disabled in directory sync settings."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            sync_settings = DirectorySyncSettings(
                id="sync-001",
                password_sync_enabled=True,
                seamless_sso_enabled=False,
            )
            entra_client.directory_sync_settings = [sync_settings]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra directory sync sync-001 has Seamless SSO disabled."
            )
            assert result[0].resource_id == "sync-001"
            assert result[0].resource_name == "Directory Sync sync-001"
            assert result[0].location == "global"

    def test_seamless_sso_enabled(self):
        """Test FAIL when Seamless SSO is enabled in directory sync settings."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            sync_settings = DirectorySyncSettings(
                id="sync-001",
                password_sync_enabled=True,
                seamless_sso_enabled=True,
            )
            entra_client.directory_sync_settings = [sync_settings]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra directory sync sync-001 has Seamless SSO enabled, which can be exploited for lateral movement and brute force attacks."
            )
            assert result[0].resource_id == "sync-001"
            assert result[0].resource_name == "Directory Sync sync-001"
            assert result[0].location == "global"

    def test_multiple_sync_settings_mixed(self):
        """Test mixed results with multiple directory sync configurations."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            sync_settings_1 = DirectorySyncSettings(
                id="sync-001",
                password_sync_enabled=True,
                seamless_sso_enabled=True,
            )
            sync_settings_2 = DirectorySyncSettings(
                id="sync-002",
                password_sync_enabled=True,
                seamless_sso_enabled=False,
            )
            entra_client.directory_sync_settings = [sync_settings_1, sync_settings_2]
            entra_client.directory_sync_error = None
            entra_client.organizations = []

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sync-001"
            assert result[1].status == "PASS"
            assert result[1].resource_id == "sync-002"

    def test_cloud_only_no_sync_settings(self):
        """Test PASS for cloud-only tenant with no directory sync settings."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            org = Organization(
                id="org1",
                name="Cloud Only Org",
                on_premises_sync_enabled=False,
            )
            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = None
            entra_client.organizations = [org]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra organization Cloud Only Org is cloud-only (no on-premises sync), Seamless SSO is not applicable."
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Cloud Only Org"

    def test_insufficient_permissions_error(self):
        """Test FAIL when there's a permission error reading directory sync settings."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            org = Organization(
                id="org1",
                name="Prowler Org",
                on_premises_sync_enabled=True,
            )
            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = "Insufficient privileges to read directory sync settings. Required permission: OnPremDirectorySynchronization.Read.All or OnPremDirectorySynchronization.ReadWrite.All"
            entra_client.organizations = [org]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Cannot verify Seamless SSO status" in result[0].status_extended
            assert "Insufficient privileges" in result[0].status_extended
            assert (
                "OnPremDirectorySynchronization.Read.All" in result[0].status_extended
            )
            assert result[0].resource_id == "org1"
            assert result[0].resource_name == "Prowler Org"

    def test_insufficient_permissions_cloud_only_passes(self):
        """Test PASS for cloud-only org even when there's a permission error."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            # Cloud-only org (on_premises_sync_enabled=False)
            org = Organization(
                id="org1",
                name="Cloud Only Org",
                on_premises_sync_enabled=False,
            )
            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = (
                "Insufficient privileges to read directory sync settings."
            )
            entra_client.organizations = [org]

            check = entra_seamless_sso_disabled()
            result = check.execute()

            # Should PASS because cloud-only orgs don't need this permission
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "cloud-only" in result[0].status_extended
            assert result[0].resource_id == "org1"

    def test_empty_everything(self):
        """Test no findings when both sync settings and organizations are empty."""
        entra_client = mock.MagicMock()
        entra_client.directory_sync_settings = []
        entra_client.directory_sync_error = None
        entra_client.organizations = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_seamless_sso_disabled.entra_seamless_sso_disabled import (
                entra_seamless_sso_disabled,
            )

            check = entra_seamless_sso_disabled()
            result = check.execute()

            assert len(result) == 0
