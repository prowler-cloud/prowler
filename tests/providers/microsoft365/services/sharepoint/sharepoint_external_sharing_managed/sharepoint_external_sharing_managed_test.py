from unittest import mock

from prowler.providers.microsoft365.services.sharepoint.sharepoint_service import (
    SharePointSettings,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_sharepoint_external_sharing_managed:
    def test_external_sharing_invalid_mode(self):
        """
        Test when sharingDomainRestrictionMode is set to an invalid value (not "allowList" ni "blockList"):
        The check should FAIL with the default message.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserSharingOnly",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=True,
                    sharingDomainRestrictionMode="none",
                )
            }

            check = sharepoint_external_sharing_managed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SharePoint external sharing is not managed through domain restrictions."
            )
            assert result[0].resource_id == DOMAIN

    def test_allow_list_empty(self):
        """
        Test when sharingDomainRestrictionMode is "allowList" but AllowedDomainList is empty:
        The check should FAIL with a message indicating the list is empty.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserSharingOnly",
                    sharingAllowedDomainList=[],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=True,
                    sharingDomainRestrictionMode="allowList",
                )
            }

            check = sharepoint_external_sharing_managed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SharePoint external sharing is managed through domain restrictions with mode 'allowList' but the list is empty."
            )
            assert result[0].resource_id == DOMAIN

    def test_block_list_empty(self):
        """
        Test when sharingDomainRestrictionMode is "blockList" but BlockedDomainList is empty:
        The check should FAIL with a message indicating the list is empty.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserSharingOnly",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=[],
                    modernAuthentication=True,
                    sharingDomainRestrictionMode="blockList",
                )
            }

            check = sharepoint_external_sharing_managed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SharePoint external sharing is managed through domain restrictions with mode 'blockList' but the list is empty."
            )
            assert result[0].resource_id == DOMAIN

    def test_allow_list_non_empty(self):
        """
        Test when sharingDomainRestrictionMode is "allowList" and AllowedDomainList is not empty:
        The check should PASS.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserSharingOnly",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=True,
                    sharingDomainRestrictionMode="allowList",
                )
            }

            check = sharepoint_external_sharing_managed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SharePoint external sharing is managed through domain restrictions with mode 'allowList'."
            )
            assert result[0].resource_id == DOMAIN

    def test_block_list_non_empty(self):
        """
        Test when sharingDomainRestrictionMode is "blockList" and BlockedDomainList is not empty:
        The check should PASS.
        """
        sharepoint_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            sharepoint_client.settings = {
                DOMAIN: SharePointSettings(
                    id=DOMAIN,
                    sharingCapability="ExternalUserSharingOnly",
                    sharingAllowedDomainList=["allowed-domain.com"],
                    sharingBlockedDomainList=["blocked-domain.com"],
                    modernAuthentication=True,
                    sharingDomainRestrictionMode="blockList",
                )
            }

            check = sharepoint_external_sharing_managed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SharePoint external sharing is managed through domain restrictions with mode 'blockList'."
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
                "prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed.sharepoint_client",
                new=sharepoint_client,
            ),
        ):
            from prowler.providers.microsoft365.services.sharepoint.sharepoint_external_sharing_managed.sharepoint_external_sharing_managed import (
                sharepoint_external_sharing_managed,
            )

            check = sharepoint_external_sharing_managed()
            result = check.execute()
            assert len(result) == 0
