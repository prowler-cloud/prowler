from unittest import mock
from uuid import uuid4

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_admincenter_groups_not_public_visibility:
    def test_admincenter_no_groups(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility.admincenter_client",
            new=admincenter_client,
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility import (
                admincenter_groups_not_public_visibility,
            )

            admincenter_client.groups = {}

            check = admincenter_groups_not_public_visibility()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_user_no_admin(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility.admincenter_client",
            new=admincenter_client,
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility import (
                admincenter_groups_not_public_visibility,
            )
            from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
                Group,
            )

            id_group1 = str(uuid4())

            admincenter_client.groups = {
                id_group1: Group(id=id_group1, name="Group1", visibility="Private"),
            }

            check = admincenter_groups_not_public_visibility()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Group Group1 has Private visibility."
            assert result[0].resource == {
                "id": id_group1,
                "name": "Group1",
                "visibility": "Private",
            }
            assert result[0].resource_name == "Group1"
            assert result[0].resource_id == id_group1
            assert result[0].location == "global"

    def test_admincenter_user_admin_compliant_license(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_microsoft365_provider(),
        ), mock.patch(
            "prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility.admincenter_client",
            new=admincenter_client,
        ):
            from prowler.providers.microsoft365.services.admincenter.admincenter_groups_not_public_visibility.admincenter_groups_not_public_visibility import (
                admincenter_groups_not_public_visibility,
            )
            from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
                Group,
            )

            id_group1 = str(uuid4())

            admincenter_client.groups = {
                id_group1: Group(id=id_group1, name="Group1", visibility="Private"),
            }

            check = admincenter_groups_not_public_visibility()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Group Group1 has Private visibility."
            assert result[0].resource == {
                "id": id_group1,
                "name": "Group1",
                "visibility": "Private",
            }
            assert result[0].resource_name == "Group1"
            assert result[0].resource_id == id_group1
            assert result[0].location == "global"
