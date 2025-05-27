import uuid
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
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
        sharepoint_client = SharePoint(
            set_mocked_m365_provider(identity=M365IdentityInfo(tenant_domain=DOMAIN))
        )
        assert sharepoint_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_settings(self):
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
