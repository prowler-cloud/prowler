from unittest import mock

from prowler.providers.aws.services.iam.iam_service import Policy, Role
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ROLE_NAME = "payment-role"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"
MANAGER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:payment-manager/example"
CREATE = "bedrock-agentcore:CreatePaymentSession"
PROCESS = "bedrock-agentcore:ProcessPayment"
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_payments_process_payment_role_separation.bedrockagentcore_payments_process_payment_role_separation"


def _statement(action, effect="Allow", resource=MANAGER_ARN, **extra):
    return {"Effect": effect, "Action": action, "Resource": resource, **extra}


def _run(inline=None, attached=None, roles=None, is_service_role=False):
    """Run the check for one role whose inline policies are {name: statements or None}.

    ``attached`` maps a managed policy ARN to its statements; None means the document is unreadable.
    """
    inline = inline or {}
    attached = attached or {}
    policies = {}
    for name, statements in inline.items():
        policies[f"{ROLE_ARN}:policy/{name}"] = statements
    policies.update(attached)
    if roles is None:
        roles = [
            Role(
                name=ROLE_NAME,
                arn=ROLE_ARN,
                assume_role_policy={},
                is_service_role=is_service_role,
                attached_policies=[
                    {"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}
                    for arn in attached
                ],
                inline_policies=list(inline),
                tags=[],
            )
        ]
    iam_client = mock.MagicMock()
    iam_client.roles = None if roles == "unlisted" else roles
    iam_client.policies = {
        arn: Policy(
            name=arn.rsplit("/", 1)[-1],
            arn=arn,
            entity="id",
            version_id="v1",
            type="Custom",
            attached=True,
            document=(
                {"Version": "2012-10-17", "Statement": statements}
                if statements is not None
                else None
            ),
        )
        for arn, statements in policies.items()
    }
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
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_payments_process_payment_role_separation.bedrockagentcore_payments_process_payment_role_separation import (
            bedrockagentcore_payments_process_payment_role_separation,
        )

        return bedrockagentcore_payments_process_payment_role_separation().execute()


class Test_bedrockagentcore_payments_process_payment_role_separation:
    def test_no_roles(self):
        assert _run(roles=[]) == []

    def test_roles_not_listed_is_manual(self):
        result = _run(roles="unlisted")
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    def test_role_without_payment_actions_is_skipped(self):
        assert _run(inline={"s3": [_statement("s3:GetObject", resource="*")]}) == []

    def test_service_role_is_skipped(self):
        assert (
            _run(inline={"p": [_statement([CREATE, PROCESS])]}, is_service_role=True)
            == []
        )

    def test_one_action_passes(self):
        result = _run(inline={"p": [_statement(CREATE)]})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"IAM Role {ROLE_NAME} allows {CREATE} but not both payment actions."
        )
        assert result[0].resource_id == ROLE_NAME
        assert result[0].resource_arn == ROLE_ARN

    def test_both_actions_fail(self):
        result = _run(inline={"p": [_statement([CREATE, PROCESS])]})
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"IAM Role {ROLE_NAME} allows both {CREATE} and {PROCESS}."
        )

    def test_actions_split_across_policies_fail(self):
        result = _run(
            inline={"create": [_statement(CREATE)]},
            attached={
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/process": [
                    _statement(PROCESS)
                ]
            },
        )
        assert result[0].status == "FAIL"

    def test_wildcards_fail(self):
        for action in (
            "*",
            "*:*",
            "bedrock-agentcore:*",
            "BEDROCK-AGENTCORE:*payment*",
        ):
            result = _run(inline={"p": [_statement(action, resource="*")]})
            assert result[0].status == "FAIL", action

    def test_prefix_wildcard_reaching_one_action_passes(self):
        result = _run(inline={"p": [_statement("bedrock-agentcore:Process*")]})
        assert result[0].status == "PASS"

    def test_not_action_excluding_process_payment_passes(self):
        statement = {"Effect": "Allow", "NotAction": PROCESS, "Resource": "*"}
        assert _run(inline={"p": [statement]})[0].status == "PASS"

    def test_unconditional_deny_in_another_policy_wins(self):
        result = _run(
            inline={
                "allow": [_statement([CREATE, PROCESS])],
                "deny": [_statement(PROCESS, effect="Deny", resource="*")],
            }
        )
        assert result[0].status == "PASS"

    def test_resource_scoped_deny_is_not_credited(self):
        result = _run(
            inline={
                "allow": [_statement([CREATE, PROCESS], resource="*")],
                "deny": [_statement(PROCESS, effect="Deny")],
            }
        )
        assert result[0].status == "FAIL"

    def test_conditional_deny_is_not_credited(self):
        deny = _statement(
            PROCESS,
            effect="Deny",
            resource="*",
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        )
        result = _run(inline={"allow": [_statement([CREATE, PROCESS])], "deny": [deny]})
        assert result[0].status == "FAIL"

    def test_unreadable_policy_is_manual(self):
        result = _run(inline={"allow": [_statement(CREATE)], "broken": None})
        assert result[0].status == "MANUAL"
        assert "broken" in result[0].status_extended

    def test_unreadable_policy_does_not_hide_a_fail(self):
        result = _run(inline={"allow": [_statement([CREATE, PROCESS])], "broken": None})
        assert result[0].status == "FAIL"

    def test_bare_dict_statement_is_read(self):
        result = _run(inline={"p": _statement([CREATE, PROCESS])})
        assert result[0].status == "FAIL"

    def test_malformed_statement_is_ignored(self):
        result = _run(inline={"p": ["not-a-statement", _statement(CREATE)]})
        assert result[0].status == "PASS"
