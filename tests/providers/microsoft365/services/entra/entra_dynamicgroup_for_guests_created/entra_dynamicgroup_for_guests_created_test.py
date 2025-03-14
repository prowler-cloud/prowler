from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import Group
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_dynamicgroup_for_guests_created:
    def test_no_groups(self):
        """
        Test when no groups exist:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created import (
                entra_dynamicgroup_for_guests_created,
            )

            check = entra_dynamicgroup_for_guests_created()
            result = check.execute()
            assert len(result) == 0

    def test_group_not_dynamic(self):
        """
        Test when a group exists but is not dynamic:
        The check should FAIL with the default message.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created.entra_client",
                new=entra_client,
            ),
        ):
            entra_client.groups = [
                Group(
                    id="group1",
                    name="Group 1",
                    groupTypes=["Unified"],
                    membershipRule=None,
                )
            ]

            from prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created import (
                entra_dynamicgroup_for_guests_created,
            )

            check = entra_dynamicgroup_for_guests_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "No dynamic group for guest users was found in Microsoft Entra."
            )
            assert result[0].resource_id == "group"
            assert result[0].resource_name == "Group"
            assert result[0].location == "global"
            assert result[0].resource == {}

    def test_dynamic_group_with_proper_membership_rule(self):
        """
        Test when a group is dynamic and its membership rule correctly restricts guest users:
        The check should PASS.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created.entra_client",
                new=entra_client,
            ),
        ):
            entra_client.groups = [
                Group(
                    id="group3",
                    name="Group 3",
                    groupTypes=["DynamicMembership"],
                    membershipRule='user.userType -eq "Guest"',
                )
            ]

            from prowler.providers.microsoft365.services.entra.entra_dynamicgroup_for_guests_created.entra_dynamicgroup_for_guests_created import (
                entra_dynamicgroup_for_guests_created,
            )

            check = entra_dynamicgroup_for_guests_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "A dynamic group for guest users is created in Microsoft Entra."
            )
            assert result[0].resource_id == "group3"
            assert result[0].resource_name == "Group 3"
            assert result[0].location == "global"
            assert result[0].resource == entra_client.groups[0].dict()
