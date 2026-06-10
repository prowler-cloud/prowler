from json import dumps
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

AGENT_ID = "test-agent-id"
AGENT_NAME = "test-agent-name"
AGENT_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:agent/{AGENT_ID}"
)
ROLE_NAME = "AmazonBedrockExecutionRoleForAgents_test"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"
BOUNDARY_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/AgentBoundary"

ASSUME_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

BOUNDARY_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}],
}

NARROW_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-rag-bucket/*"],
        }
    ],
}

BROAD_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


# Mock both ListAgents and GetAgent at the botocore level. moto's bedrock-agent
# support is incomplete for our needs (GetAgent often doesn't echo back the
# role ARN we set), so we control the responses directly. We also need to keep
# IAM calls going to moto.
make_api_call = botocore.client.BaseClient._make_api_call


def _mock_bedrock_agent_factory(role_arn):
    """Return a mock_make_api_call function that returns role_arn from GetAgent.

    Pass role_arn=None to simulate an agent whose role can't be resolved.
    """

    def _mock_make_api_call(self, operation_name, kwarg):
        if operation_name == "ListAgents":
            return {
                "agentSummaries": [
                    {"agentId": AGENT_ID, "agentName": AGENT_NAME},
                ]
            }
        if operation_name == "GetAgent":
            return {
                "agent": {
                    "agentId": AGENT_ID,
                    "agentName": AGENT_NAME,
                    "agentResourceRoleArn": role_arn,
                }
            }
        if operation_name == "ListTagsForResource":
            return {"tags": {}}
        if operation_name == "ListPrompts":
            return {"promptSummaries": []}
        return make_api_call(self, operation_name, kwarg)

    return _mock_make_api_call


def _setup_role(
    *,
    attached_policy_arns=(),
    inline_policies=None,
    permissions_boundary=None,
):
    """Create an IAM role in moto with the given configuration. Returns the role ARN."""
    iam = client("iam", region_name=AWS_REGION_US_EAST_1)

    if permissions_boundary:
        iam.create_policy(
            PolicyName="AgentBoundary",
            PolicyDocument=dumps(BOUNDARY_POLICY_DOCUMENT),
        )

    create_kwargs = {
        "RoleName": ROLE_NAME,
        "AssumeRolePolicyDocument": dumps(ASSUME_ROLE_POLICY_DOCUMENT),
    }
    if permissions_boundary:
        create_kwargs["PermissionsBoundary"] = permissions_boundary
    iam.create_role(**create_kwargs)

    for policy_arn in attached_policy_arns:
        iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=policy_arn)

    for policy_name, policy_document in (inline_policies or {}).items():
        iam.put_role_policy(
            RoleName=ROLE_NAME,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

    return ROLE_ARN


def _run_check(role_arn_for_get_agent):
    """Build the IAM + BedrockAgent services, patch them in, run the check."""
    from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent
    from prowler.providers.aws.services.iam.iam_service import IAM

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_bedrock_agent_factory(role_arn_for_get_agent),
    ):
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege import (
                bedrock_agent_role_least_privilege,
            )

            return bedrock_agent_role_least_privilege().execute()


class Test_bedrock_agent_role_least_privilege:
    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_no_agents(self):
        """No agents in the account -> zero findings."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_role_least_privilege.bedrock_agent_role_least_privilege import (
                bedrock_agent_role_least_privilege,
            )

            assert bedrock_agent_role_least_privilege().execute() == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_compliant(self):
        """Narrow inline policy + boundary + no *FullAccess attached -> PASS."""
        role_arn = _setup_role(
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
            permissions_boundary=BOUNDARY_ARN,
        )

        result = _run_check(role_arn_for_get_agent=role_arn)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "follows least privilege" in result[0].status_extended
        assert result[0].resource_id == AGENT_ID
        assert result[0].resource_arn == AGENT_ARN

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_full_access_attached(self):
        """AmazonBedrockFullAccess attached -> FAIL."""
        role_arn = _setup_role(
            attached_policy_arns=("arn:aws:iam::aws:policy/AmazonBedrockFullAccess",),
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
            permissions_boundary=BOUNDARY_ARN,
        )

        result = _run_check(role_arn_for_get_agent=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "grants full access" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_administrator_access_attached(self):
        """AdministratorAccess attached (no FullAccess suffix) -> FAIL via doc-based admin check."""
        role_arn = _setup_role(
            attached_policy_arns=("arn:aws:iam::aws:policy/AdministratorAccess",),
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
            permissions_boundary=BOUNDARY_ARN,
        )

        result = _run_check(role_arn_for_get_agent=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "managed policy AdministratorAccess grants administrative access"
            in result[0].status_extended
        )

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_resource_star_broad_action(self):
        """Inline statement with Action:* on Resource:* -> FAIL."""
        role_arn = _setup_role(
            inline_policies={"BroadAccess": BROAD_INLINE_POLICY},
            permissions_boundary=BOUNDARY_ARN,
        )

        result = _run_check(role_arn_for_get_agent=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "grants administrative access" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_no_permissions_boundary(self):
        """Otherwise clean role but missing permissions boundary -> FAIL."""
        role_arn = _setup_role(
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
            permissions_boundary=None,
        )

        result = _run_check(role_arn_for_get_agent=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no permissions boundary configured" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_agent_role_not_resolvable(self):
        """role_arn returned by GetAgent doesn't match any IAM role -> FAIL."""
        result = _run_check(
            role_arn_for_get_agent=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/does-not-exist"
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "could not be resolved" in result[0].status_extended
