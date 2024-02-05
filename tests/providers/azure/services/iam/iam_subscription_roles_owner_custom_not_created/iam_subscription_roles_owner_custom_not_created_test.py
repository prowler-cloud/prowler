from unittest import mock
from uuid import uuid4

from azure.mgmt.authorization.v2022_04_01.models import Permission

from prowler.providers.azure.services.iam.iam_service import Role
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_iam_subscription_roles_owner_custom_not_created:
    def test_iam_no_roles(self):
        defender_client = mock.MagicMock
        defender_client.custom_roles = {}

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 0

    def test_iam_custom_owner_role_created_with_all(self):
        defender_client = mock.MagicMock
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION: [
                Role(
                    id=str(uuid4()),
                    name=role_name,
                    type="CustomRole",
                    assignable_scopes=["/*"],
                    permissions=[Permission(actions="*")],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION} is a custom owner role."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].resource_id
                == defender_client.custom_roles[AZURE_SUBSCRIPTION][0].id
            )
            assert result[0].resource_name == role_name

    def test_iam_custom_owner_role_created_with_no_permissions(self):
        defender_client = mock.MagicMock
        role_name = "test-role"
        defender_client.custom_roles = {
            AZURE_SUBSCRIPTION: [
                Role(
                    id=str(uuid4()),
                    name=role_name,
                    type="type-role",
                    assignable_scopes=[""],
                    permissions=[Permission()],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created.iam_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.iam.iam_subscription_roles_owner_custom_not_created.iam_subscription_roles_owner_custom_not_created import (
                iam_subscription_roles_owner_custom_not_created,
            )

            check = iam_subscription_roles_owner_custom_not_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Role {role_name} from subscription {AZURE_SUBSCRIPTION} is not a custom owner role."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert (
                result[0].resource_id
                == defender_client.custom_roles[AZURE_SUBSCRIPTION][0].id
            )
            assert result[0].resource_name == role_name
