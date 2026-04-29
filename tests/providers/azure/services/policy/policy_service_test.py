from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.policy.policy_service import (
    Policy,
    PolicyAssigment,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


def mock_policy_assigments(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "policy-1": PolicyAssigment(
                id="id-1", name="policy-1", enforcement_mode="Default"
            )
        }
    }


@patch(
    "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
    new=mock_policy_assigments,
)
class Test_Policy_Service:
    def test_get_client(self):
        policy = Policy(set_mocked_azure_provider())
        assert (
            policy.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__ == "PolicyClient"
        )

    def test__get_subscriptions__(self):
        policy = Policy(set_mocked_azure_provider())
        assert policy.subscriptions.__class__.__name__ == "dict"

    def test_get_policy_assigments(self):
        policy = Policy(set_mocked_azure_provider())
        assert policy.policy_assigments.__class__.__name__ == "dict"
        assert (
            policy.policy_assigments[AZURE_SUBSCRIPTION_ID].__class__.__name__ == "dict"
        )
        assert (
            policy.policy_assigments[AZURE_SUBSCRIPTION_ID][
                "policy-1"
            ].__class__.__name__
            == "PolicyAssigment"
        )
        assert policy.policy_assigments[AZURE_SUBSCRIPTION_ID]["policy-1"].id == "id-1"
        assert (
            policy.policy_assigments[AZURE_SUBSCRIPTION_ID]["policy-1"].enforcement_mode
            == "Default"
        )


class Test_Policy_get_policy_assigments:
    def test_get_policy_assigments_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.policy_assignments.list.return_value = []

        with patch(
            "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
            return_value={},
        ):
            policy = Policy(set_mocked_azure_provider())

        policy.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        policy.resource_groups = None

        result = policy._get_policy_assigments()

        mock_client.policy_assignments.list.assert_called_once()
        mock_client.policy_assignments.list_for_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_policy_assigments_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
            return_value={},
        ):
            policy = Policy(set_mocked_azure_provider())

        policy.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        policy.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = policy._get_policy_assigments()

        mock_client.policy_assignments.list_for_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.policy_assignments.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_policy_assigments_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with patch(
            "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
            return_value={},
        ):
            policy = Policy(set_mocked_azure_provider())

        policy.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        policy.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = policy._get_policy_assigments()

        mock_client.policy_assignments.list_for_resource_group.assert_not_called()
        mock_client.policy_assignments.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_policy_assigments_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
            return_value={},
        ):
            policy = Policy(set_mocked_azure_provider())

        policy.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        policy.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = policy._get_policy_assigments()

        assert mock_client.policy_assignments.list_for_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_policy_assigments_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.policy.policy_service.Policy._get_policy_assigments",
            return_value={},
        ):
            policy = Policy(set_mocked_azure_provider())

        policy.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        policy.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        policy._get_policy_assigments()

        mock_client.policy_assignments.list_for_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
