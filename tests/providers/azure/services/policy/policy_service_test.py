from unittest.mock import patch

from prowler.providers.azure.services.policy.policy_service import (
    Policy,
    PolicyAssigment,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_policy_assigments(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "policy-1": PolicyAssigment(id="id-1", enforcement_mode="Default")
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
