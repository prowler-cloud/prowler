from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM, Policy
from tests.providers.aws.utils import (
    ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.bedrock.bedrock_guardrail_iam_condition_enforcement_enabled.bedrock_guardrail_iam_condition_enforcement_enabled"
GUARDRAIL_ARN = (
    f"arn:aws:bedrock:us-east-1:{AWS_ACCOUNT_NUMBER}:guardrail/abcd1234efgh:1"
)
MODEL_ARN_PATTERN = "arn:aws:bedrock:us-east-1::foundation-model/*"
INVOKE_ACTIONS = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]


def _policy(
    statements,
    name: str = "policy",
    policy_type: str = "Custom",
    attached: bool = True,
    document_present: bool = True,
    entity: str = "ANPAEXAMPLEPOLICYID",
):
    """Build a Policy model; a missing document reproduces a failed GetPolicyVersion call."""
    document = None
    if document_present:
        document = {"Version": "2012-10-17", "Statement": statements}
    return Policy(
        name=name,
        arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/{name}",
        entity=entity,
        version_id="v1",
        type=policy_type,
        attached=attached,
        document=document,
    )


def _run(policies: list, scan_unused_services: bool = True):
    """Execute the check against the given Policy models and return its reports."""
    iam_client = mock.MagicMock()
    iam_client.policies = {policy.arn: policy for policy in policies}
    iam_client.region = AWS_REGION_US_EAST_1
    iam_client.provider = mock.MagicMock(scan_unused_services=scan_unused_services)

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.aws.services.bedrock.bedrock_guardrail_iam_condition_enforcement_enabled.bedrock_guardrail_iam_condition_enforcement_enabled import (
            bedrock_guardrail_iam_condition_enforcement_enabled,
        )

        return bedrock_guardrail_iam_condition_enforcement_enabled().execute()


def _allow(action=None, resource=MODEL_ARN_PATTERN, condition=None, **extra):
    statement = {"Effect": "Allow", "Resource": resource}
    if action is not None:
        statement["Action"] = action
    if condition is not None:
        statement["Condition"] = condition
    statement.update(extra)
    return statement


def _deny(action=INVOKE_ACTIONS, resource="*", condition=None):
    statement = {"Effect": "Deny", "Action": action, "Resource": resource}
    if condition is not None:
        statement["Condition"] = condition
    return statement


REQUIRE_GUARDRAIL = {"StringEquals": {"bedrock:GuardrailIdentifier": GUARDRAIL_ARN}}


class Test_bedrock_guardrail_iam_condition_enforcement_enabled:
    def test_no_policies(self):
        assert _run([]) == []

    def test_policy_without_bedrock_invocation_not_reported(self):
        policy = _policy(
            [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        )
        assert _run([policy]) == []

    def test_other_bedrock_actions_not_reported(self):
        """Only the two actions that accept the condition key are in scope."""
        policy = _policy(
            [_allow(["bedrock:ListFoundationModels", "bedrock:ApplyGuardrail"], "*")]
        )
        assert _run([policy]) == []

    def test_admin_star_action_left_to_admin_checks(self):
        policy = _policy([_allow("*", "*")])
        assert _run([policy]) == []

    def test_aws_managed_policy_not_evaluated(self):
        policy = _policy([_allow("bedrock:*", "*")], policy_type="AWS")
        assert _run([policy]) == []

    def test_unattached_custom_policy_follows_scan_unused_services(self):
        policy = _policy([_allow(INVOKE_ACTIONS)], attached=False)
        assert _run([policy], scan_unused_services=False) == []
        result = _run([policy], scan_unused_services=True)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_custom_policy_without_condition_fails(self):
        policy = _policy([_allow(INVOKE_ACTIONS)], name="bedrock-invoke")
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Custom policy bedrock-invoke allows bedrock:InvokeModel, "
            "bedrock:InvokeModelWithResponseStream without requiring the "
            "bedrock:GuardrailIdentifier condition key, so models can be invoked "
            "without a guardrail."
        )
        assert result[0].resource_id == "bedrock-invoke"
        assert (
            result[0].resource_arn
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/bedrock-invoke"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_custom_policy_with_condition_passes(self):
        policy = _policy(
            [_allow(INVOKE_ACTIONS, condition=REQUIRE_GUARDRAIL)],
            name="bedrock-invoke",
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "Custom policy bedrock-invoke allows Bedrock model invocation only when "
            "the bedrock:GuardrailIdentifier condition key is satisfied."
        )

    def test_aws_documented_allow_and_deny_pattern_passes(self):
        """The policy from the Amazon Bedrock user guide, Example 1."""
        policy = _policy(
            [
                _allow(INVOKE_ACTIONS, condition=REQUIRE_GUARDRAIL),
                _deny(
                    resource=[MODEL_ARN_PATTERN],
                    condition={
                        "StringNotEquals": {
                            "bedrock:GuardrailIdentifier": GUARDRAIL_ARN
                        }
                    },
                ),
                _allow(
                    "bedrock:ApplyGuardrail",
                    f"arn:aws:bedrock:us-east-1:{AWS_ACCOUNT_NUMBER}:guardrail/abcd1234efgh",
                ),
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_condition_key_and_operator_are_case_insensitive(self):
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={"stringlike": {"BEDROCK:guardrailIdentifier": "*"}},
                )
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_partial_enforcement_reports_only_the_open_action(self):
        policy = _policy(
            [
                _allow("bedrock:InvokeModel", condition=REQUIRE_GUARDRAIL),
                _allow("bedrock:InvokeModelWithResponseStream"),
            ],
            name="mixed",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert "bedrock:InvokeModelWithResponseStream without" in (
            result[0].status_extended
        )
        assert "bedrock:InvokeModel," not in result[0].status_extended

    def test_if_exists_operator_does_not_enforce(self):
        """StringEqualsIfExists is true when the request names no guardrail."""
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={
                        "StringEqualsIfExists": {
                            "bedrock:GuardrailIdentifier": GUARDRAIL_ARN
                        }
                    },
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_negated_operator_on_allow_does_not_enforce(self):
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={
                        "StringNotEquals": {"bedrock:GuardrailIdentifier": "other"}
                    },
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_for_all_values_does_not_enforce(self):
        """ForAllValues is vacuously true when the key is absent."""
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={
                        "ForAllValues:StringEquals": {
                            "bedrock:GuardrailIdentifier": GUARDRAIL_ARN
                        }
                    },
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_null_false_requires_a_guardrail(self):
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={"Null": {"bedrock:GuardrailIdentifier": "false"}},
                )
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_null_true_on_allow_does_not_enforce(self):
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={"Null": {"bedrock:GuardrailIdentifier": "true"}},
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_other_condition_key_does_not_enforce(self):
        policy = _policy(
            [
                _allow(
                    INVOKE_ACTIONS,
                    condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_actions_are_expanded(self):
        for action in ["bedrock:*", "bedrock:Invoke*", "bedrock:InvokeModel*", "*:*"]:
            policy = _policy([_allow(action, "*")])
            result = _run([policy])
            if action == "*:*":
                assert result == []
            else:
                assert result[0].status == "FAIL", action

    def test_action_pattern_not_reaching_invoke_is_ignored(self):
        policy = _policy([_allow("bedrock:Get*", "*")])
        assert _run([policy]) == []

    def test_resource_outside_bedrock_is_ignored(self):
        policy = _policy([_allow("bedrock:InvokeModel", "arn:aws:s3:::bucket/*")])
        assert _run([policy]) == []

    def test_short_arn_with_star_reaches_bedrock(self):
        policy = _policy([_allow("bedrock:InvokeModel", "arn:aws:*")])
        assert _run([policy])[0].status == "FAIL"

    def test_not_resource_is_treated_as_reaching_bedrock(self):
        statement = {
            "Effect": "Allow",
            "Action": "bedrock:InvokeModel",
            "NotResource": "arn:aws:s3:::bucket",
        }
        assert _run([_policy([statement])])[0].status == "FAIL"

    def test_not_action_allow_grants_invocation(self):
        statement = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
        result = _run([_policy([statement])])
        assert result[0].status == "FAIL"

    def test_not_action_allow_excluding_invocation_is_ignored(self):
        statement = {"Effect": "Allow", "NotAction": "bedrock:*", "Resource": "*"}
        assert _run([_policy([statement])]) == []

    def test_unconditional_deny_on_all_resources_clears_finding(self):
        policy = _policy([_allow(INVOKE_ACTIONS), _deny()])
        assert _run([policy])[0].status == "PASS"

    def test_deny_when_guardrail_missing_clears_finding(self):
        policy = _policy(
            [
                _allow(INVOKE_ACTIONS),
                _deny(condition={"Null": {"bedrock:GuardrailIdentifier": "true"}}),
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_deny_on_narrower_resource_does_not_clear_finding(self):
        policy = _policy(
            [
                _allow(INVOKE_ACTIONS, "*"),
                _deny(
                    resource=MODEL_ARN_PATTERN,
                    condition={"Null": {"bedrock:GuardrailIdentifier": "true"}},
                ),
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_with_single_character_wildcard_does_not_cover_star(self):
        policy = _policy(
            [
                _allow("bedrock:InvokeModel", "arn:aws:bedrock:us-east-1::*"),
                _deny("bedrock:InvokeModel", "arn:aws:bedrock:us-east-1::?"),
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_pattern_covering_concrete_allow_arn_clears_finding(self):
        model = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2"
        policy = _policy(
            [
                _allow("bedrock:InvokeModel", model),
                _deny("bedrock:InvokeModel", MODEL_ARN_PATTERN),
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_deny_with_extra_condition_key_does_not_clear_finding(self):
        policy = _policy(
            [
                _allow(INVOKE_ACTIONS),
                _deny(
                    condition={
                        "Null": {"bedrock:GuardrailIdentifier": "true"},
                        "StringEquals": {"aws:RequestedRegion": "eu-west-1"},
                    }
                ),
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_covering_one_action_leaves_the_other(self):
        policy = _policy(
            [_allow(INVOKE_ACTIONS), _deny("bedrock:InvokeModel")],
            name="half",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert "allows bedrock:InvokeModelWithResponseStream without" in (
            result[0].status_extended
        )

    def test_single_statement_document_as_dict(self):
        policy = _policy([])
        policy.document = {
            "Version": "2012-10-17",
            "Statement": _allow("bedrock:InvokeModel"),
        }
        assert _run([policy])[0].status == "FAIL"

    def test_missing_document_is_manual(self):
        policy = _policy([], name="unreadable", document_present=False)
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Custom policy unreadable could not be evaluated because its policy "
            "document was not retrieved."
        )

    def test_inline_policy_fails_with_entity_in_resource_id(self):
        policy = _policy(
            [_allow(INVOKE_ACTIONS)],
            name="invoke",
            policy_type="Inline",
            entity="app-role",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "app-role/invoke"
        assert result[0].status_extended.startswith(
            "Inline policy invoke of app-role allows"
        )

    @mock_aws
    def test_iam_service_end_to_end(self):
        """Custom and inline policies collected by the real IAM service through moto."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam = client("iam", region_name=AWS_REGION_US_EAST_1)
        role_name = "bedrock-app"
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY),
        )["Role"]["Arn"]
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="invoke-open",
            PolicyDocument=dumps(
                {"Version": "2012-10-17", "Statement": [_allow(INVOKE_ACTIONS)]}
            ),
        )
        enforced_arn = iam.create_policy(
            PolicyName="invoke-guarded",
            PolicyDocument=dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [_allow(INVOKE_ACTIONS, condition=REQUIRE_GUARDRAIL)],
                }
            ),
        )["Policy"]["Arn"]
        iam.attach_role_policy(RoleName=role_name, PolicyArn=enforced_arn)

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_iam_condition_enforcement_enabled.bedrock_guardrail_iam_condition_enforcement_enabled import (
                bedrock_guardrail_iam_condition_enforcement_enabled,
            )

            result = bedrock_guardrail_iam_condition_enforcement_enabled().execute()

        by_id = {report.resource_id: report for report in result}
        assert len(result) == 2
        assert by_id[f"{role_name}/invoke-open"].status == "FAIL"
        assert by_id[f"{role_name}/invoke-open"].resource_arn == role_arn
        assert by_id["invoke-guarded"].status == "PASS"
        assert by_id["invoke-guarded"].resource_arn == enforced_arn
