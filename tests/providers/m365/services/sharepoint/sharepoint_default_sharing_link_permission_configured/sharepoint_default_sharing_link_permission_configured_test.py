import uuid
from unittest import mock

from prowler.providers.m365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_sharepoint_default_sharing_link_permission_configured:
    def test_sharepoint_default_sharing_link_permission_configured_view(self):
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured import (
                sharepoint_default_sharing_link_permission_configured,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=[],
                sharingBlockedDomainList=[],
                sharingDomainRestrictionMode="none",
                resharingEnabled=False,
                legacyAuth=False,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
                defaultLinkPermission="View",
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SharePoint default sharing link permission is set to 'View'."
            )
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource_id == "sharepointSettings"

    def test_sharepoint_default_sharing_link_permission_configured_edit(self):
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured import (
                sharepoint_default_sharing_link_permission_configured,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=[],
                sharingBlockedDomainList=[],
                sharingDomainRestrictionMode="none",
                resharingEnabled=False,
                legacyAuth=False,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
                defaultLinkPermission="Edit",
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SharePoint default sharing link permission is set to 'Edit'."
            )
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource_id == "sharepointSettings"

    def test_sharepoint_default_sharing_link_permission_none(self):
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured import (
                sharepoint_default_sharing_link_permission_configured,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=[],
                sharingBlockedDomainList=[],
                sharingDomainRestrictionMode="none",
                resharingEnabled=False,
                legacyAuth=False,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
                defaultLinkPermission=None,
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 0
