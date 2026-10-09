"""Tests for entra_directory_sync_object_identifier_update_bypass_disabled check."""

from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DirectorySyncSettings,
    Organization,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_directory_sync_object_identifier_update_bypass_disabled."
    "entra_directory_sync_object_identifier_update_bypass_disabled"
)


def _hybrid_org():
    """Return a hybrid organization fixture."""
    return Organization(
        id="org-001",
        name="Hybrid Org",
        on_premises_sync_enabled=True,
    )


def _cloud_only_org():
    """Return a cloud-only organization fixture."""
    return Organization(
        id="org-001",
        name="Cloud Only Org",
        on_premises_sync_enabled=False,
    )


class Test_entra_directory_sync_object_identifier_update_bypass_disabled:
    """Tests for the onPremisesObjectIdentifier update bypass check."""

    def test_no_organizations_manual(self):
        """MANUAL when the organization cannot be read (hybrid status unknown)."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.organizations = []
            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = None

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "organization could not be read" in result[0].status_extended

    def test_bypass_disabled(self):
        """PASS when bypass is disabled on a hybrid tenant."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    allow_on_prem_update_of_on_premises_object_identifier_enabled=False,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = [_hybrid_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sync-001"
            assert result[0].resource_name == "Directory Sync sync-001"
            assert (
                "hard-match security protections enforced" in result[0].status_extended
            )
            assert "bypass is disabled" in result[0].status_extended

    def test_bypass_enabled(self):
        """FAIL when bypass is enabled on a hybrid tenant."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    allow_on_prem_update_of_on_premises_object_identifier_enabled=True,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = [_hybrid_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sync-001"
            assert result[0].resource_name == "Directory Sync sync-001"
            assert (
                "allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled"
                in result[0].status_extended
            )
            assert "weakens hard-match protections" in result[0].status_extended

    def test_bypass_none_manual(self):
        """MANUAL when bypass property is absent (None) from the response."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="sync-001",
                    allow_on_prem_update_of_on_premises_object_identifier_enabled=None,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = [_hybrid_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "sync-001"
            assert result[0].resource_name == "Directory Sync sync-001"
            assert "did not return" in result[0].status_extended
            assert (
                "Get-MgDirectoryOnPremiseSynchronization" in result[0].status_extended
            )

    def test_cloud_only_tenant(self):
        """PASS when tenant is cloud-only."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = None
            entra_client.organizations = [_cloud_only_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Cloud Only Org"
            assert "cloud-only" in result[0].status_extended
            assert "not applicable" in result[0].status_extended

    def test_cloud_only_tenant_with_sync_object_returned(self):
        """PASS for cloud-only tenants even when Graph returns a sync object.

        Microsoft Graph returns an onPremisesSynchronization object (with all
        features disabled) for cloud-only tenants. The check must not treat the
        disabled flags as a finding when on-premises sync is not enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = [
                DirectorySyncSettings(
                    id="tenant-id",
                    allow_on_prem_update_of_on_premises_object_identifier_enabled=True,
                )
            ]
            entra_client.directory_sync_error = None
            entra_client.organizations = [_cloud_only_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Cloud Only Org"
            assert "cloud-only" in result[0].status_extended

    def test_permission_error_hybrid(self):
        """MANUAL when permissions are insufficient for a hybrid tenant."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = "Insufficient privileges"
            entra_client.organizations = [_hybrid_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Hybrid Org"
            assert "Cannot verify" in result[0].status_extended
            assert "Insufficient privileges" in result[0].status_extended

    def test_permission_error_cloud_only(self):
        """PASS when settings cannot be read but the tenant is cloud-only."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = "Insufficient privileges"
            entra_client.organizations = [_cloud_only_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "org-001"
            assert "cloud-only" in result[0].status_extended

    def test_hybrid_no_settings_returned(self):
        """MANUAL when a hybrid tenant returns no directory sync settings."""
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_directory_sync_object_identifier_update_bypass_disabled.entra_directory_sync_object_identifier_update_bypass_disabled import (
                entra_directory_sync_object_identifier_update_bypass_disabled,
            )

            entra_client.directory_sync_settings = []
            entra_client.directory_sync_error = None
            entra_client.organizations = [_hybrid_org()]

            check = entra_directory_sync_object_identifier_update_bypass_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Hybrid Org"
            assert (
                "no directory sync settings were returned" in result[0].status_extended
            )
