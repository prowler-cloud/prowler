import uuid
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo, M365RegionConfig
from prowler.providers.m365.services.sharepoint.sharepoint_service import (
    SharePoint,
    SharePointSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

uuid_value = uuid.uuid4()


async def mock_sharepoint_get_settings(_):
    return SharePointSettings(
        sharingCapability="ExternalUserAndGuestSharing",
        sharingAllowedDomainList=["allowed-domain.com"],
        sharingBlockedDomainList=["blocked-domain.com"],
        sharingDomainRestrictionMode="allowList",
        resharingEnabled=False,
        legacyAuth=True,
        allowedDomainGuidsForSyncApp=[uuid_value],
    )


@patch(
    "prowler.providers.m365.services.sharepoint.sharepoint_service.SharePoint._get_settings",
    new=mock_sharepoint_get_settings,
)
class Test_SharePoint_Service:
    def test_get_client(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
            sharepoint_client = SharePoint(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
        assert sharepoint_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_settings(self):
        with patch("prowler.providers.m365.lib.service.service.M365PowerShell"):
            sharepoint_client = SharePoint(set_mocked_m365_provider())
        settings = sharepoint_client.settings
        assert settings.sharingCapability == "ExternalUserAndGuestSharing"
        assert settings.sharingAllowedDomainList == ["allowed-domain.com"]
        assert settings.sharingBlockedDomainList == ["blocked-domain.com"]
        assert settings.sharingDomainRestrictionMode == "allowList"
        assert settings.resharingEnabled is False
        assert settings.legacyAuth is True
        assert settings.allowedDomainGuidsForSyncApp == [uuid_value]
        assert len(settings.allowedDomainGuidsForSyncApp) == 1


class Test_SharePoint_PowerShell_Initialization:
    def test_failed_connection_skips_tenant_configuration(self):
        with (
            patch(
                "prowler.providers.m365.lib.service.service.M365PowerShell"
            ) as powershell_class,
            patch.object(
                SharePoint,
                "_get_settings",
                new=mock_sharepoint_get_settings,
            ),
        ):
            powershell = powershell_class.return_value
            powershell.connect_sharepoint_online.return_value = False

            sharepoint_client = SharePoint(
                set_mocked_m365_provider(
                    azure_region_config=M365RegionConfig(name="M365Global")
                )
            )

        powershell.connect_sharepoint_online.assert_called_once_with("M365Global")
        powershell.get_sharepoint_tenant_config.assert_not_called()
        powershell.close.assert_called_once_with()
        assert sharepoint_client.tenant_settings is None
        assert sharepoint_client.settings.sharingCapability == (
            "ExternalUserAndGuestSharing"
        )

    def test_certificate_connection_enriches_graph_settings(self):
        with (
            patch(
                "prowler.providers.m365.lib.service.service.M365PowerShell"
            ) as powershell_class,
            patch.object(
                SharePoint,
                "_get_settings",
                new=mock_sharepoint_get_settings,
            ),
        ):
            powershell = powershell_class.return_value
            powershell.connect_sharepoint_online.return_value = True
            powershell.get_sharepoint_tenant_config.return_value = {
                "DefaultLinkPermission": "View"
            }

            sharepoint_client = SharePoint(
                set_mocked_m365_provider(
                    azure_region_config=M365RegionConfig(name="M365China")
                )
            )

        powershell.connect_sharepoint_online.assert_called_once_with("M365China")
        powershell.get_sharepoint_tenant_config.assert_called_once_with()
        powershell.close.assert_called_once_with()
        assert sharepoint_client.tenant_settings == {"DefaultLinkPermission": "View"}
        assert sharepoint_client.settings.sharingCapability == (
            "ExternalUserAndGuestSharing"
        )
