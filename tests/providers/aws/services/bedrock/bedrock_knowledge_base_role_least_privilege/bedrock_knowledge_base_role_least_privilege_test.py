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

KB_ID = "test-kb-id"
KB_NAME = "test-kb-name"
KB_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:knowledge-base/{KB_ID}"
ROLE_NAME = "AmazonBedrockExecutionRoleForKnowledgeBase_test"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"

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

NARROW_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"],
            "Resource": [KB_ARN],
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::kb-data-bucket",
                "arn:aws:s3:::kb-data-bucket/*",
            ],
        },
    ],
}

BEDROCK_STAR_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": KB_ARN}],
}

RETRIEVE_STAR_RESOURCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"],
            "Resource": "*",
        }
    ],
}

BROAD_MANAGED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}],
}

DENY_MITIGATED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock:*", "Resource": KB_ARN},
        {"Effect": "Deny", "Action": "bedrock:*", "Resource": "*"},
    ],
}

SCOPED_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock:Retrieve", "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "bedrock:Retrieve",
            "Resource": "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/OTHERKB123",
        },
    ],
}

CONDITIONAL_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "bedrock:Retrieve", "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "bedrock:Retrieve",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalTag/team": "red"}},
        },
    ],
}

INVOKE_WILDCARD_ALLOW_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "bedrock:Invoke*", "Resource": "*"}],
}

INVOKE_WILDCARD_GLOBAL_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "bedrock:Invoke*", "Resource": "*"}],
}

INVOKE_WILDCARD_SCOPED_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "bedrock:Invoke*",
            "Resource": KB_ARN,
        },
    ],
}


# Mock ListKnowledgeBases and GetKnowledgeBase at the botocore level. We control
# the responses directly and keep IAM calls going to moto.
make_api_call = botocore.client.BaseClient._make_api_call


def _mock_bedrock_agent_factory(role_arn, get_kb_error=None, summaries=()):
    """Return a mock_make_api_call returning the given KB summaries and role ARN.

    Pass get_kb_error as a ClientError code to make GetKnowledgeBase fail,
    simulating a KB whose service role cannot be retrieved.
    """

    def _mock_make_api_call(self, operation_name, kwarg):
        if operation_name == "ListKnowledgeBases":
            return {"knowledgeBaseSummaries": list(summaries)}
        if operation_name == "GetKnowledgeBase":
            if get_kb_error is not None:
                raise botocore.exceptions.ClientError(
                    {
                        "Error": {
                            "Code": get_kb_error,
                            "Message": "Simulated GetKnowledgeBase failure",
                        }
                    },
                    "GetKnowledgeBase",
                )
            return {
                "knowledgeBase": {
                    "knowledgeBaseId": KB_ID,
                    "name": KB_NAME,
                    "roleArn": role_arn,
                }
            }
        if operation_name == "ListTagsForResource":
            return {"tags": {}}
        return make_api_call(self, operation_name, kwarg)

    return _mock_make_api_call


KB_SUMMARY = {
    "knowledgeBaseId": KB_ID,
    "name": KB_NAME,
    "knowledgeBaseArn": KB_ARN,
}


def _setup_role(
    *,
    managed_policy_documents=(),
    inline_policies=None,
):
    """Create an IAM role in moto with the given configuration. Returns the role ARN."""
    iam = client("iam", region_name=AWS_REGION_US_EAST_1)

    iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
    )

    for policy_name, policy_document in managed_policy_documents:
        policy_arn = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )["Policy"]["Arn"]
        iam.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=policy_arn)

    for policy_name, policy_document in (inline_policies or {}).items():
        iam.put_role_policy(
            RoleName=ROLE_NAME,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )

    return ROLE_ARN


def _run_check(
    *,
    role_arn_for_get_kb=None,
    get_kb_error=None,
    summaries=(KB_SUMMARY,),
    patch_iam=None,
    patch_bedrock=None,
):
    """Build the IAM + BedrockAgent services, patch them in, run the check."""
    from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent
    from prowler.providers.aws.services.iam.iam_service import IAM

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_bedrock_agent_factory(role_arn_for_get_kb, get_kb_error, summaries),
    ):
        bedrock_service = BedrockAgent(aws_provider)
        iam_service = IAM(aws_provider)
        if patch_iam:
            patch_iam(iam_service)
        if patch_bedrock:
            patch_bedrock(bedrock_service)
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_knowledge_base_role_least_privilege.bedrock_knowledge_base_role_least_privilege.bedrock_agent_client",
                new=bedrock_service,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_knowledge_base_role_least_privilege.bedrock_knowledge_base_role_least_privilege.iam_client",
                new=iam_service,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_knowledge_base_role_least_privilege.bedrock_knowledge_base_role_least_privilege import (
                bedrock_knowledge_base_role_least_privilege,
            )

            return bedrock_knowledge_base_role_least_privilege().execute()


class Test_bedrock_knowledge_base_role_least_privilege:
    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_no_knowledge_bases(self):
        """No knowledge bases in the account -> zero findings."""
        result = _run_check(summaries=())
        assert result == []

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_compliant(self):
        """Narrow inline policy scoped to the KB ARN -> PASS."""
        role_arn = _setup_role(inline_policies={"NarrowAccess": NARROW_INLINE_POLICY})

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "follows least privilege" in result[0].status_extended
        assert result[0].resource_id == KB_ID
        assert result[0].resource_arn == KB_ARN

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_bedrock_star_inline(self):
        """Inline policy with bedrock:* -> FAIL."""
        role_arn = _setup_role(
            inline_policies={"BroadAccess": BEDROCK_STAR_INLINE_POLICY}
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "bedrock:*" in result[0].status_extended
        assert "inline policy BroadAccess" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_bedrock_actions_star_resource(self):
        """Bedrock retrieval actions on Resource:* -> FAIL."""
        role_arn = _setup_role(
            inline_policies={"StarResource": RETRIEVE_STAR_RESOURCE_POLICY}
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "on all resources (*)" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_broad_managed_policy_attached(self):
        """Customer-managed policy granting bedrock:* attached -> FAIL."""
        role_arn = _setup_role(
            managed_policy_documents=[("BroadBedrock", BROAD_MANAGED_POLICY)],
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "managed policy BroadBedrock" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_deny_cancels_violation(self):
        """Explicit Deny for bedrock:* cancels the Allow wildcard -> PASS."""
        role_arn = _setup_role(inline_policies={"DenyMitigated": DENY_MITIGATED_POLICY})

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_scoped_deny_does_not_cancel_violation(self):
        """A Deny scoped to one ARN does not cancel a broad Allow -> FAIL."""
        role_arn = _setup_role(inline_policies={"ScopedDeny": SCOPED_DENY_POLICY})

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "on all resources (*)" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_conditional_deny_does_not_cancel_violation(self):
        """A conditional Deny does not cancel a broad Allow -> FAIL."""
        role_arn = _setup_role(
            inline_policies={"ConditionalDeny": CONDITIONAL_DENY_POLICY}
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "on all resources (*)" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_role_not_resolvable(self):
        """roleArn returned by GetKnowledgeBase doesn't match any IAM role -> MANUAL."""
        result = _run_check(
            role_arn_for_get_kb=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/does-not-exist"
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be resolved in IAM" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_detail_call_fails(self):
        """GetKnowledgeBase raises -> detail_retrieved False -> MANUAL."""
        _setup_role(inline_policies={"NarrowAccess": NARROW_INLINE_POLICY})

        result = _run_check(get_kb_error="AccessDeniedException")

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_iam_roles_not_listed(self):
        """iam:ListRoles denied (roles is None) -> single account-level MANUAL."""
        role_arn = _setup_role(inline_policies={"NarrowAccess": NARROW_INLINE_POLICY})

        result = _run_check(
            role_arn_for_get_kb=role_arn,
            patch_iam=lambda iam_service: setattr(iam_service, "roles", None),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "IAM roles could not be listed" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_kb_list_scan_error(self):
        """ListKnowledgeBases failure recorded for the region -> region MANUAL."""
        result = _run_check(
            summaries=(),
            patch_bedrock=lambda bedrock_service: bedrock_service.knowledge_bases_scan_errors.update(
                {AWS_REGION_US_EAST_1: "AccessDeniedException"}
            ),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be listed" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_unreadable_policy_gives_manual(self):
        """A policy whose document cannot be read -> MANUAL, not a silent PASS."""
        role_arn = _setup_role(
            managed_policy_documents=[("BroadBedrock", BROAD_MANAGED_POLICY)],
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
        )

        def _drop_policy_documents(iam_service):
            # Simulate GetPolicyVersion/GetRolePolicy failures: the IAM service
            # has the policy references on the role but no documents for them.
            iam_service.policies = {}

        result = _run_check(
            role_arn_for_get_kb=role_arn, patch_iam=_drop_policy_documents
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be read" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_violation_still_fails_with_unreadable_policy(self):
        """A real violation still FAILs even when another policy is unreadable."""
        role_arn = _setup_role(
            managed_policy_documents=[("BroadBedrock", BROAD_MANAGED_POLICY)],
            inline_policies={"NarrowAccess": NARROW_INLINE_POLICY},
        )

        def _drop_inline_policy_document(iam_service):
            # Simulate a GetRolePolicy failure for the inline policy only.
            iam_service.policies.pop(f"{ROLE_ARN}:policy/NarrowAccess", None)

        result = _run_check(
            role_arn_for_get_kb=role_arn, patch_iam=_drop_inline_policy_document
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "managed policy BroadBedrock" in result[0].status_extended

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_unscoped_deny_in_other_policy_cancels_violation(self):
        """An unscoped Deny in one policy cancels a broad Allow in another -> PASS.

        IAM evaluates a role's identity policies together, so the Deny in the
        inline policy means the managed policy's wildcard can never be used.
        """
        role_arn = _setup_role(
            managed_policy_documents=[("WideAllow", INVOKE_WILDCARD_ALLOW_POLICY)],
            inline_policies={"GlobalDeny": INVOKE_WILDCARD_GLOBAL_DENY_POLICY},
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_scoped_deny_in_other_policy_does_not_cancel_violation(self):
        """A scoped Deny in another policy does not cancel a broad Allow -> FAIL."""
        role_arn = _setup_role(
            managed_policy_documents=[("WideAllow", INVOKE_WILDCARD_ALLOW_POLICY)],
            inline_policies={"ScopedDeny": INVOKE_WILDCARD_SCOPED_DENY_POLICY},
        )

        result = _run_check(role_arn_for_get_kb=role_arn)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "managed policy WideAllow" in result[0].status_extended
