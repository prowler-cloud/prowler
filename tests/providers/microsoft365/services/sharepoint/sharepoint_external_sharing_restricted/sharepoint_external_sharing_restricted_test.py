from unittest import mock

from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_sharepoint_external_sharing_restricted:
    def test_external_sharing_restricted(self):
        """
        Test when sharingCapability is set to an allowed value (e.g. "ExternalUserSharingOnly"):
        The check should PASS because external sharing is restricted.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted import (
                sharepoint_external_sharing_restricted,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserSharingOnly",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                modernAuthentication=True,
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_external_sharing_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "External sharing is restricted to external user sharing or more restrictive."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == {
                "sharingCapability": "ExternalUserSharingOnly",
                "sharingAllowedDomainList": ["allowed-domain.com"],
                "sharingBlockedDomainList": ["blocked-domain.com"],
                "sharingDomainRestrictionMode": "allowList",
                "resharingEnabled": False,
                "modernAuthentication": True,
            }

    def test_external_sharing_not_restricted(self):
        """
        Test when sharingCapability is set to a non-restricted value (e.g. "ExternalUserAndGuestSharing"):
        The check should FAIL because external sharing is not restricted.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted import (
                sharepoint_external_sharing_restricted,
            )

            sharepoint_client.settings = SharePointSettings(
                sharingCapability="ExternalUserAndGuestSharing",
                sharingAllowedDomainList=["allowed-domain.com"],
                sharingBlockedDomainList=["blocked-domain.com"],
                sharingDomainRestrictionMode="allowList",
                resharingEnabled=False,
                modernAuthentication=True,
            )
            sharepoint_client.tenant_domain = DOMAIN

            check = sharepoint_external_sharing_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "External sharing is not restricted and guests users can access."
            )
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "SharePoint Settings"
            assert result[0].resource == {
                "sharingCapability": "ExternalUserAndGuestSharing",
                "sharingAllowedDomainList": ["allowed-domain.com"],
                "sharingBlockedDomainList": ["blocked-domain.com"],
                "sharingDomainRestrictionMode": "allowList",
                "resharingEnabled": False,
                "modernAuthentication": True,
            }

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
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_restricted.sharepoint_external_sharing_restricted import (
                sharepoint_external_sharing_restricted,
            )

            check = sharepoint_external_sharing_restricted()
            result = check.execute()
            assert len(result) == 0
