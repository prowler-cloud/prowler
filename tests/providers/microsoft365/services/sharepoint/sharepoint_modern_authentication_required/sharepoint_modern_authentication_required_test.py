from unittest import mock

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_sharepoint_modern_authentication_required:
    def test_sharepoint_modern_authentication_disabled(self):
        """
        Test when modernAuthentication is False:
        The check should PASS, as SharePoint does not allow access to apps that don't use modern authentication.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
                SharePointSettings,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserAndGuestSharing",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=False,
                )
            }

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Microsoft 365 SharePoint does not allow access to apps that don't use modern authentication."
            )
            assert result[0].resource_id == DOMAIN

    def test_sharepoint_modern_authentication_enabled(self):
        """
        Test when modernAuthentication is True:
        The check should FAIL, as SharePoint allows access to apps that don't use modern authentication.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
                SharePointSettings,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserAndGuestSharing",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=True,
                )
            }

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Microsoft 365 SharePoint allows access to apps that don't use modern authentication."
            )
            assert result[0].resource_id == DOMAIN

    def test_sharepoint_empty_settings(self):
        """
        Test when sharepoint_client.settings is empty:
        The check should return an empty list of findings.
        """
        sharepoint_client = mock.MagicMock
        sharepoint_client.settings = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_modern_authentication_required.sharepoint_modern_authentication_required import (
                sharepoint_modern_authentication_required,
            )

            check = sharepoint_modern_authentication_required()
            result = check.execute()
            assert len(result) == 0
