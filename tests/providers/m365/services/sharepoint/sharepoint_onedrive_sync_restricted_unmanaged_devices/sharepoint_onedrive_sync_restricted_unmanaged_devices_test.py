import uuid
from unittest import mock

from prowler.providers.m365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_sharepoint_onedrive_sync_restricted_unmanaged_devices:
    def test_no_allowed_domain_guids(self):
        """
        Test when there are no allowed domain guids for OneDrive sync app


        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices import (
                sharepoint_onedrive_sync_restricted_unmanaged_devices,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                legacyAuth=True,
                resharingEnabled=False,
                sharingDomainRestrictionMode="none",
                allowedDomainGuidsForSyncApp=[],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_onedrive_sync_restricted_unmanaged_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Microsoft 365 SharePoint allows OneDrive sync to unmanaged devices."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_allowed_domain_guids(self):
        """
        Test when there are allowed domain guids for OneDrive sync app
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices import (
                sharepoint_onedrive_sync_restricted_unmanaged_devices,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=[],
                sharingBlockedDomainList=["blocked-domain.com"],
                legacyAuth=True,
                resharingEnabled=False,
                sharingDomainRestrictionMode="allowList",
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_onedrive_sync_restricted_unmanaged_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Microsoft 365 SharePoint does not allow OneDrive sync to unmanaged devices."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_empty_settings(self):
        """
        Test when sharepoint_client.settings is empty:
        The check should return an empty list of findings.
        """
        sharepoint_client = mock.MagicMock
        sharepoint_client.settings = {}
        sharepoint_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_onedrive_sync_restricted_unmanaged_devices.sharepoint_onedrive_sync_restricted_unmanaged_devices import (
                sharepoint_onedrive_sync_restricted_unmanaged_devices,
            )

            check = sharepoint_onedrive_sync_restricted_unmanaged_devices()
            result = check.execute()

            assert len(result) == 0
