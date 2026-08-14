import uuid
from unittest import mock

from prowler.providers.m365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_sharepoint_default_sharing_link_permission_configured:
    def test_default_sharing_link_permission_view(self):
        """
        Test when defaultLinkPermission is set to "View":
        The check should PASS because the default sharing link permission is set to View.
        """
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
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                legacyAuth=True,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
                defaultLinkPermission="View",
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "The default sharing link permission is set to View."
            )
            assert result[0].resource_id == "sharepointSettings"
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_default_sharing_link_permission_edit(self):
        """
        Test when defaultLinkPermission is set to "Edit":
        The check should FAIL because the default sharing link permission is set to Edit instead of View.
        """
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
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                legacyAuth=True,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
                defaultLinkPermission="Edit",
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "The default sharing link permission is set to Edit instead of View."
            )
            assert result[0].resource_id == "sharepointSettings"
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
            mock.patch("prowler.providers.m365.lib.service.service.M365PowerShell"),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_default_sharing_link_permission_configured.sharepoint_default_sharing_link_permission_configured import (
                sharepoint_default_sharing_link_permission_configured,
            )

            check = sharepoint_default_sharing_link_permission_configured()
            result = check.execute()
            assert len(result) == 0
