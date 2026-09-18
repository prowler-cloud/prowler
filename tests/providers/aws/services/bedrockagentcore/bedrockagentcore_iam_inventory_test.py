"""Tests that an unreadable IAM inventory is reported, not read as compliance.

The three AgentCore checks that reason over IAM select roles by what their
policies grant. That makes an unreadable policy document the exact place a
violating grant would hide, and a denied ListRoles the difference between a clean
account and an unexamined one. None of it may be reported as PASS or as silence.
"""

from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/test-agentcore-role"
ROLE_NAME = "test-agentcore-role"
POLICY_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/test-policy"
ROLE_ARN_TEMPLATE = f"arn:aws:iam:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:role"

# The two checks driven purely by the IAM inventory.
IAM_ONLY_CHECKS = (
    "bedrockagentcore_full_access_policy_attached",
    "bedrockagentcore_payments_process_payment_role_separation",
)


class _Role:
    """Minimal stand-in for the IAM service Role model."""

    def __init__(self, attached_policies=None, inline_policies=None):
        self.arn = ROLE_ARN
        self.name = ROLE_NAME
        self.attached_policies = (
            attached_policies
            if attached_policies is not None
            else [{"PolicyArn": POLICY_ARN, "PolicyName": "test-policy"}]
        )
        self.inline_policies = inline_policies or []


def _iam_client(roles, policies=None):
    """Build a stub IAM client exposing what these checks read."""
    client = mock.MagicMock()
    client.roles = roles
    # An empty inventory is what iam_service leaves when a policy document could
    # not be fetched: the key is simply absent.
    client.policies = policies if policies is not None else {}
    client.region = AWS_REGION_US_EAST_1
    client.audited_account = AWS_ACCOUNT_NUMBER
    client.role_arn_template = ROLE_ARN_TEMPLATE
    return client


def _run_iam_only(check_name, iam_client):
    """Execute an IAM-driven check against a stub IAM client."""
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=aws_provider,
    ):
        module = __import__(
            f"prowler.providers.aws.services.bedrockagentcore.{check_name}.{check_name}",
            fromlist=[check_name],
        )
        with mock.patch.object(module, "iam_client", iam_client):
            return getattr(module, check_name)().execute()


class Test_denied_list_roles_is_reported:
    """iam_service sets roles to None on AccessDenied, distinct from empty."""

    @mock_aws
    def test_roles_none_yields_manual_not_silence(self):
        """A denied ListRoles must not read as an account with no roles.

        Iterating None as an empty list would report a clean scan for an IAM
        inventory nobody was allowed to see.
        """
        for check_name in IAM_ONLY_CHECKS:
            results = _run_iam_only(check_name, _iam_client(roles=None))

            assert len(results) == 1, check_name
            assert results[0].status == "MANUAL", check_name
            assert results[0].region == AWS_REGION_US_EAST_1
            assert results[0].resource_id == AWS_ACCOUNT_NUMBER
            assert results[0].resource_arn == ROLE_ARN_TEMPLATE
            assert "could not be listed" in results[0].status_extended
            assert results[0].status_extended.endswith(".")

    @mock_aws
    def test_empty_role_list_yields_no_findings(self):
        """An account genuinely holding no roles is not a MANUAL."""
        for check_name in IAM_ONLY_CHECKS:
            assert _run_iam_only(check_name, _iam_client(roles=[])) == [], check_name


class Test_unreadable_policy_keeps_the_role_in_scope:
    """The unreadable document is where the disqualifying grant would be."""

    @mock_aws
    def test_only_unreadable_policy_yields_manual(self):
        """A role whose sole policy is unreadable must not drop out silently.

        Both checks decide relevance from what a policy grants. When the only
        policy cannot be read, relevance is unknown -- so skipping the role
        reports nothing about a role that may well be in scope and violating.
        """
        for check_name in IAM_ONLY_CHECKS:
            results = _run_iam_only(check_name, _iam_client(roles=[_Role()]))

            assert len(results) == 1, check_name
            assert results[0].status == "MANUAL", check_name
            assert "could not be retrieved" in results[0].status_extended
            assert results[0].status_extended.endswith(".")
            # The message must not trail an empty action list or assert a grant
            # that only the unreadable document could have established.
            assert "bedrock-agentcore:," not in results[0].status_extended
            assert not results[0].status_extended.endswith("allows .")

    @mock_aws
    def test_role_with_no_policies_at_all_is_skipped(self):
        """Nothing unreadable and nothing granted means nothing to report."""
        role = _Role(attached_policies=[], inline_policies=[])
        for check_name in IAM_ONLY_CHECKS:
            assert (
                _run_iam_only(check_name, _iam_client(roles=[role])) == []
            ), check_name
