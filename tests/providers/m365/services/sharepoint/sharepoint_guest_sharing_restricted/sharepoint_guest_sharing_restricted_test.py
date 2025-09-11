import uuid
from unittest import mock

from prowler.providers.m365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_sharepoint_guest_sharing_restricted:
    def test_guest_sharing_restricted(self):
        """
        Test when resharingEnabled is False:
        The check should PASS because guest sharing is restricted.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                legacyAuth=True,
                resharingEnabled=False,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest sharing is restricted; guest users cannot share items they do not own."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_guest_sharing_not_restricted(self):
        """
        Test when resharingEnabled is True:
        The check should FAIL because guest sharing is not restricted.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                legacyAuth=True,
                resharingEnabled=True,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest sharing is not restricted; guest users can share items they do not own."
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
                "prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 0
