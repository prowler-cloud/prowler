from unittest import mock

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ROLE_NAME = "agentcore-role"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"
AGENTCORE_FULL_ACCESS_ARN = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
REGISTRY_FULL_ACCESS_ARN = "arn:aws:iam::aws:policy/AgentRegistryFullAccess"
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached"


def _role(policy_arns=(), is_service_role=False):
    return Role(
        name=ROLE_NAME,
        arn=ROLE_ARN,
        assume_role_policy={},
        is_service_role=is_service_role,
        attached_policies=[
            {"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}
            for arn in policy_arns
        ],
        tags=[],
    )


def _run(roles):
    iam_client = mock.MagicMock()
    iam_client.roles = roles
    iam_client.region = AWS_REGION_US_EAST_1
    iam_client.audited_account = AWS_ACCOUNT_NUMBER
    iam_client.role_arn_template = (
        f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:role"
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_full_access_policy_attached.bedrockagentcore_full_access_policy_attached import (
            bedrockagentcore_full_access_policy_attached,
        )

        return bedrockagentcore_full_access_policy_attached().execute()


class Test_bedrockagentcore_full_access_policy_attached:
    def test_no_roles(self):
        assert _run([]) == []

    def test_roles_not_listed_is_manual(self):
        result = _run(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    def test_service_role_is_skipped(self):
        assert _run([_role([AGENTCORE_FULL_ACCESS_ARN], is_service_role=True)]) == []

    def test_role_without_full_access_passes(self):
        result = _run([_role(["arn:aws:iam::aws:policy/ReadOnlyAccess"])])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"IAM Role {ROLE_NAME} does not have BedrockAgentCoreFullAccess or AgentRegistryFullAccess policy attached."
        )
        assert result[0].resource_id == ROLE_NAME
        assert result[0].resource_arn == ROLE_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_agentcore_full_access_fails(self):
        result = _run([_role([AGENTCORE_FULL_ACCESS_ARN])])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"IAM Role {ROLE_NAME} has BedrockAgentCoreFullAccess policy attached."
        )

    def test_agent_registry_full_access_fails(self):
        result = _run([_role([REGISTRY_FULL_ACCESS_ARN])])
        assert result[0].status == "FAIL"
        assert "AgentRegistryFullAccess" in result[0].status_extended

    def test_both_policies_are_named_in_sorted_order(self):
        result = _run([_role([REGISTRY_FULL_ACCESS_ARN, AGENTCORE_FULL_ACCESS_ARN])])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"IAM Role {ROLE_NAME} has AgentRegistryFullAccess and BedrockAgentCoreFullAccess policy attached."
        )

    def test_govcloud_managed_policy_fails(self):
        result = _run(
            [_role(["arn:aws-us-gov:iam::aws:policy/BedrockAgentCoreFullAccess"])]
        )
        assert result[0].status == "FAIL"

    def test_customer_managed_policy_with_same_name_passes(self):
        result = _run(
            [
                _role(
                    [
                        f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/BedrockAgentCoreFullAccess",
                        f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/TeamBedrockAgentCoreFullAccess",
                    ]
                )
            ]
        )
        assert result[0].status == "PASS"
