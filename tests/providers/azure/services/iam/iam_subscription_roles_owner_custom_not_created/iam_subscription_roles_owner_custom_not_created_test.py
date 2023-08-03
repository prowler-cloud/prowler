from unittest import mock
from uuid import uuid4

from azure.mgmt.authorization.v2022_04_01.models import Permission

from prowler.providers.azure.services.iam.iam_service import Role

AZURE_SUSCRIPTION = str(uuid4())


class Test_defender_ensure_defender_for_storage_is_on:
    def test_iam_no_roles(self):
        defender_client = mock.MagicMock
        defender_client.roles = {}

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
        defender_client.roles = {
            AZURE_SUSCRIPTION: [
                Role(
                    id=str(uuid4()),
                    name=role_name,
                    type="type-role",
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
                == f"Role {role_name} from subscription {AZURE_SUSCRIPTION} is a custom owner role"
            )

    def test_iam_custom_owner_role_created_with_no_permissions(self):
        defender_client = mock.MagicMock
        role_name = "test-role"
        defender_client.roles = {
            AZURE_SUSCRIPTION: [
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
                == f"Role {role_name} from subscription {AZURE_SUSCRIPTION} is not a custom owner role"
            )
