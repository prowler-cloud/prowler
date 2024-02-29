from unittest.mock import patch

from prowler.providers.azure.services.policy.policy_service import (
    Policy,
    PolicyAssigment,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_policy_assigments(_):
    return {
        AZURE_SUBSCRIPTION: {
            "policy-1": PolicyAssigment(id="id-1", enforcement_mode="Default")
        }
    }


@patch(
    "prowler.providers.azure.services.policy.policy_service.Policy.__get_policy_assigments__",
    new=mock_policy_assigments,
)
class Test_AppInsights_Service:
    def test__get_client__(self):
        policy = Policy(set_mocked_azure_audit_info())
        assert policy.clients[AZURE_SUBSCRIPTION].__class__.__name__ == "PolicyClient"

    def test__get_subscriptions__(self):
        policy = Policy(set_mocked_azure_audit_info())
        assert policy.subscriptions.__class__.__name__ == "dict"

    def test__get_policy_assigments__(self):
        policy = Policy(set_mocked_azure_audit_info())
        assert policy.policy_assigments.__class__.__name__ == "dict"
        assert policy.policy_assigments[AZURE_SUBSCRIPTION].__class__.__name__ == "dict"
        assert (
            policy.policy_assigments[AZURE_SUBSCRIPTION]["policy-1"].__class__.__name__
            == "PolicyAssigment"
        )
        assert policy.policy_assigments[AZURE_SUBSCRIPTION]["policy-1"].id == "id-1"
        assert (
            policy.policy_assigments[AZURE_SUBSCRIPTION]["policy-1"].enforcement_mode
            == "Default"
        )
