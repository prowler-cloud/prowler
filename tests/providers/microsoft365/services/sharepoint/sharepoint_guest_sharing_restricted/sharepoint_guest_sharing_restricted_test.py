from unittest import mock

from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


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
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            # Configuramos los settings para el dominio con resharingEnabled en False (restricción aplicada)
            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="irrelevant",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    sharingDomainRestrictionMode="allowList",
                    modernAuthentication=True,
                    resharingEnabled=False,
                )
            }

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest sharing is restricted; guest users cannot share items they do not own."
            )
            assert result[0].resource_id == DOMAIN

    def test_guest_sharing_not_restricted(self):
        """
        Test when resharingEnabled is True:
        The check should FAIL because guest sharing is not restricted.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="irrelevant",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    sharingDomainRestrictionMode="allowList",
                    modernAuthentication=True,
                    resharingEnabled=True,
                )
            }

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest sharing is not restricted; guest users can share items they do not own."
            )
            assert result[0].resource_id == DOMAIN

    def test_empty_settings(self):
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
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_guest_sharing_restricted.sharepoint_guest_sharing_restricted import (
                sharepoint_guest_sharing_restricted,
            )

            check = sharepoint_guest_sharing_restricted()
            result = check.execute()

            assert len(result) == 0
