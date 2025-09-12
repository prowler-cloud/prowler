import uuid
from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_sharepoint_modern_authentication_required:
    def test_sharepoint_modern_authentication_disabled(self):
        """
        Test when legacyAuth is False:
        The check should PASS, as SharePoint does not allow access to apps that don't use modern authentication.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )
            from prowler.providers.m365.services.sharepoint.sharepoint_service import (
                SharePointSettings,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserAndGuestSharing",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                legacyAuth=False,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Microsoft 365 SharePoint does not allow access to apps that don't use modern authentication."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_sharepoint_modern_authentication_enabled(self):
        """
        Test when legacyAuth is True:
        The check should FAIL, as SharePoint allows access to apps that don't use modern authentication.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )
            from prowler.providers.m365.services.sharepoint.sharepoint_service import (
                SharePointSettings,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserAndGuestSharing",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                legacyAuth=True,
                allowedDomainGuidsForSyncApp=[uuid.uuid4()],
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Microsoft 365 SharePoint allows access to apps that don't use modern authentication."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == sharepoint_client.settings.dict()

    def test_sharepoint_empty_settings(self):
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
                "prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.m365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 0
