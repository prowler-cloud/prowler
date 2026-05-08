from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.iam.iam_service import IAM
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)


class Test_IAM_get_roles:
    def test_get_roles_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.role_definitions.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = None

        builtin, custom = iam._get_roles()

        mock_client.role_definitions.list.assert_called_once()
        assert AZURE_SUBSCRIPTION_ID in builtin
        assert AZURE_SUBSCRIPTION_ID in custom

    def test_get_roles_with_resource_group(self):
        mock_client = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        builtin, custom = iam._get_roles()

        mock_client.role_definitions.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in builtin
        assert AZURE_SUBSCRIPTION_ID in custom

    def test_get_roles_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        builtin, custom = iam._get_roles()

        mock_client.role_definitions.list.assert_not_called()
        assert builtin[AZURE_SUBSCRIPTION_ID] == {}
        assert custom[AZURE_SUBSCRIPTION_ID] == {}


class Test_IAM_get_role_assignments:
    def test_get_role_assignments_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.role_assignments = MagicMock()
        mock_client.role_assignments.list_for_subscription.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = None

        result = iam._get_role_assignments()

        mock_client.role_assignments.list_for_subscription.assert_called_once()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_role_assignments_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.role_assignments = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = iam._get_role_assignments()

        mock_client.role_assignments.list_for_subscription.assert_not_called()
        # When resource_groups is set, the loop uses `continue` so no key is added
        assert AZURE_SUBSCRIPTION_ID not in result

    def test_get_role_assignments_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.role_assignments = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_roles",
                return_value=({}, {}),
            ),
            patch(
                "prowler.providers.azure.services.iam.iam_service.IAM._get_role_assignments",
                return_value={},
            ),
        ):
            iam = IAM(set_mocked_azure_provider())

        iam.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        iam.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = iam._get_role_assignments()

        mock_client.role_assignments.list_for_subscription.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID not in result
