from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
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
        sharingDomainRestrictionMode="allowList",
        resharingEnabled=False,
        legacyAuth=True,
    )


@patch(
    "prowler.providers.microsoft365.services.sharepoint.sharepoint_service.SharePoint._get_settings",
    new=mock_sharepoint_get_settings,
)
class Test_SharePoint_Service:
    def test_get_client(self):
        sharepoint_client = SharePoint(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert sharepoint_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_settings(self):
        sharepoint_client = SharePoint(set_mocked_microsoft365_provider())
        settings = sharepoint_client.settings
        assert settings.sharingCapability == "ExternalUserAndGuestSharing"
        assert settings.sharingAllowedDomainList == ["allowed-domain.com"]
        assert settings.sharingBlockedDomainList == ["blocked-domain.com"]
        assert settings.sharingDomainRestrictionMode == "allowList"
        assert settings.resharingEnabled is False
        assert settings.legacyAuth is True
