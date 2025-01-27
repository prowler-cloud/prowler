from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
    OneDriveSharedContent,
    SharePoint,
    SharePointSettings,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


async def mock_sharepoint_get_settings(_):
    return SharePointSettings(
        sharingCapability="ExternalUserAndGuestSharing",
        sharingAllowedDomainList=["allowed-domain.com"],
        sharingBlockedDomainList=["blocked-domain.com"],
        modernAuthentication=True,
    )


async def mock_sharepoint_get_one_drive_shared_content(_):
    return OneDriveSharedContent(
        totalSharedContent=42,
    )


@patch(
    "prowler.providers.microsoft365.services.sharepoint.sharepoint_service.SharePoint._get_settings",
    new=mock_sharepoint_get_settings,
)
@patch(
    "prowler.providers.microsoft365.services.sharepoint.sharepoint_service.SharePoint._get_one_drive_shared_content",
    new=mock_sharepoint_get_one_drive_shared_content,
)
class Test_SharePoint_Service:
    def test_get_client(self):
        """Test que verifica que el cliente de SharePoint se crea correctamente."""
        sharepoint_client = SharePoint(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert sharepoint_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_settings(self):
        """Test que verifica la obtención de configuraciones globales de SharePoint."""
        sharepoint_client = SharePoint(set_mocked_microsoft365_provider())
        assert DOMAIN in sharepoint_client.settings
        settings = sharepoint_client.settings[DOMAIN]

        # Validaciones de los valores devueltos por el mock
        assert settings.sharingCapability == "ExternalUserAndGuestSharing"
        assert settings.sharingAllowedDomainList == ["allowed-domain.com"]
        assert settings.sharingBlockedDomainList == ["blocked-domain.com"]
        assert settings.modernAuthentication is True

    def test_get_one_drive_shared_content(self):
        """Test que verifica la obtención del contenido compartido en OneDrive."""
        sharepoint_client = SharePoint(set_mocked_microsoft365_provider())
        assert DOMAIN in sharepoint_client.one_drive_shared_content
        shared_content = sharepoint_client.one_drive_shared_content[DOMAIN]

        # Validación del contenido compartido devuelto por el mock
        assert shared_content.totalSharedContent == 42
