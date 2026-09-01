from unittest import mock

import pytest

from prowler.providers.aws.services.iam.iam_service import Policy
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_ID = "123456789012"
AGENTCORE_PRINCIPAL = "bedrock-agentcore.amazonaws.com"
EVALUATION_ROLE_PREFIX_ARN = "arn:aws:iam::*:role/AgentCoreEvaluationRole*"
ANY_ROLE_IN_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/*"
AGENTCORE_ACTION_STATEMENT = {
    "Effect": "Allow",
    "Action": ["bedrock-agentcore:CreateAgentRuntime"],
    "Resource": "*",
}

CHECK_MODULE = "prowler.providers.aws.services.iam.iam_policy_passrole_to_bedrock_agentcore_restricted.iam_policy_passrole_to_bedrock_agentcore_restricted"


def _policy(
    statements,
    name: str = "policy",
    policy_type: str = "Custom",
    attached: bool = True,
    document_present: bool = True,
):
    """Build a customer-managed Policy, with the document present unless told otherwise.

    `document_present=False` reproduces a policy whose GetPolicyVersion call failed, which the
    collector leaves as a None document rather than an empty one.
    """
    document = None
    if document_present:
        document = {"Version": "2012-10-17", "Statement": statements}
    return Policy(
        name=name,
        arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/{name}",
        entity="ANPAEXAMPLEPOLICYID",
        version_id="v1",
        type=policy_type,
        attached=attached,
        document=document,
    )


def _passrole(resource, condition: dict = None, action="iam:PassRole") -> dict:
    """Build an Allow statement for iam:PassRole, omitting Resource when it is None.

    Omitting Resource entirely is the shape a NotResource statement takes, so `None` is how a
    test reaches that branch rather than a missing argument.
    """
    statement = {"Effect": "Allow", "Action": action}
    if resource is not None:
        statement["Resource"] = resource
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _passed_to(service) -> dict:
    """Build a StringEquals condition pinning iam:PassedToService to the given service."""
    return {"StringEquals": {"iam:PassedToService": service}}


def _run(policies: list, scan_unused_services: bool = True):
    """Execute the check against the given policies and return its reports.

    The policies are model objects, so the reports exercise the check's own statement parsing
    without any IAM API call.
    """
    iam_client = mock.MagicMock()
    iam_client.policies = {policy.arn: policy for policy in policies}
    iam_client.region = AWS_REGION_US_EAST_1
    iam_client.provider.scan_unused_services = scan_unused_services

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.aws.services.iam.iam_policy_passrole_to_bedrock_agentcore_restricted.iam_policy_passrole_to_bedrock_agentcore_restricted import (
            iam_policy_passrole_to_bedrock_agentcore_restricted,
        )

        return iam_policy_passrole_to_bedrock_agentcore_restricted().execute()


class Test_iam_policy_passrole_to_bedrock_agentcore_restricted:
    def test_no_policies(self):
        """An account with no customer-managed policies produces no reports at all."""
        assert len(_run([])) == 0

    def test_aws_managed_policy_not_evaluated(self):
        """An AWS-managed policy is out of the population even when it would FAIL on merit.

        The fixture is the failing shape, so a zero measures the type filter rather than an
        absence of violations.
        """
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL))], policy_type="AWS"
        )
        assert len(_run([policy])) == 0

    def test_inline_policy_not_evaluated(self):
        """An inline policy is out of the population: a separate check owns that surface."""
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL))], policy_type="Inline"
        )
        assert len(_run([policy])) == 0

    def test_unattached_policy_skipped_without_scan_unused_services(self):
        """An unattached policy is judged only when scan_unused_services is on.

        Both directions are asserted from one fixture, so the flag is shown to be what decides it.
        """
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL))], attached=False
        )
        assert len(_run([policy], scan_unused_services=False)) == 0
        assert _run([policy], scan_unused_services=True)[0].status == "FAIL"

    def test_unreadable_document_is_manual(self):
        """A policy whose document was never retrieved must be MANUAL, never PASS.

        An unread document is where an unbounded PassRole grant would hide, so claiming compliance
        from it would assert something never established.
        """
        policy = _policy([], name="unreadable", document_present=False)
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Custom Policy unreadable could not be evaluated because its policy document was not retrieved."
        )

    def test_aws_reference_evaluations_policy_passes(self):
        """AWS's own least-privilege example must PASS, and the report's identity fields are pinned.

        Taken verbatim from the AgentCore Evaluations prerequisites page: PassRole confined to a
        role-name prefix and to the AgentCore principal. A FAIL here would report AWS's documented
        guidance as a misconfiguration, which is the strongest possible false positive.
        """
        policy = _policy(
            [
                {
                    "Effect": "Allow",
                    "Action": [
                        "bedrock-agentcore:CreateEvaluator",
                        "bedrock-agentcore:CreateOnlineEvaluationConfig",
                        "bedrock-agentcore:Evaluate",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": EVALUATION_ROLE_PREFIX_ARN,
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": AGENTCORE_PRINCIPAL}
                    },
                },
            ],
            name="AgentCoreEvaluationsLeastPrivilege",
        )
        result = _run([policy])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "Custom Policy AgentCoreEvaluationsLeastPrivilege does not allow iam:PassRole "
            "to Bedrock AgentCore on every role."
        )
        assert result[0].resource_id == "AgentCoreEvaluationsLeastPrivilege"
        assert (
            result[0].resource_arn
            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/AgentCoreEvaluationsLeastPrivilege"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_wildcard_resource_pinned_to_agentcore_fails(self):
        """PassRole on Resource "*" pinned to the AgentCore principal must FAIL.

        The full sentence is asserted, so a reworded finding cannot pass silently.
        """
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL))], name="pass_any_role"
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Custom Policy pass_any_role allows iam:PassRole to Bedrock AgentCore on every "
            "role instead of the specific execution roles AgentCore is meant to run as."
        )

    def test_wildcard_resource_with_agentcore_action_in_same_policy_fails(self):
        """An unpinned PassRole is in scope when the same policy also allows an AgentCore action.

        That combination is what lets one policy both create the resource and choose the role it
        runs as, which is the escalation this check exists for.
        """
        policy = _policy([_passrole("*"), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_resource_without_agentcore_reach_passes(self):
        """An unbounded PassRole that reaches no AgentCore action and pins no service must PASS.

        It is a real finding, but a different one: the privilege-escalation checks own it, and
        reporting it here would duplicate them.
        """
        policy = _policy([_passrole("*")])
        assert _run([policy])[0].status == "PASS"

    def test_passed_to_another_service_is_out_of_scope(self):
        """PassRole pinned to another service stays out of scope even beside an AgentCore action.

        Measured live on SageMaker Studio policies. The condition confines the statement to
        sagemaker.amazonaws.com, so it cannot hand a role to AgentCore however the rest of the
        policy is shaped.
        """
        policy = _policy(
            [
                _passrole("*", _passed_to("sagemaker.amazonaws.com")),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "operator",
        [
            "StringEquals",
            "StringEqualsIfExists",
            "StringEqualsIgnoreCase",
            "StringEqualsIgnoreCaseIfExists",
            "StringLike",
            "StringLikeIfExists",
            "ForAnyValue:StringEquals",
            "ForAllValues:StringEquals",
            "ForAllValues:StringEqualsIfExists",
        ],
    )
    def test_every_spelling_of_an_agentcore_pin_fails(self, operator):
        """A pin naming AgentCore must FAIL under every operator that compares the key.

        The policy carries NO other AgentCore action, so the pin is the only thing that can put
        the statement in scope. That is what makes the case discriminating: an operator the check
        fails to read produces no values, _targets_agentcore then treats the statement as reaching
        every service and consults the document, finds no AgentCore action, and PASSes a PassRole
        grant on every role in the account. Every spelling here PASSed before the allow-list.
        """
        policy = _policy(
            [_passrole("*", {operator: {"iam:PassedToService": AGENTCORE_PRINCIPAL}})],
            name="pass_any_role",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Custom Policy pass_any_role allows iam:PassRole to Bedrock AgentCore on every "
            "role instead of the specific execution roles AgentCore is meant to run as."
        )

    @pytest.mark.parametrize(
        "operator",
        [
            "StringEquals",
            "StringEqualsIgnoreCase",
            "StringLike",
            "ForAnyValue:StringEquals",
        ],
    )
    def test_a_pin_that_cannot_be_skipped_keeps_another_service_out_of_scope(
        self, operator
    ):
        """A pin naming another service PASSes only under operators the caller cannot skip.

        The AgentCore action is present, so the document-wide fallback pulls the statement back in
        unless the condition genuinely confines it. ForAnyValue is here rather than with the
        defeasible spellings because AWS documents it as returning false for an absent key, so it
        fails closed on an Allow.
        """
        policy = _policy(
            [
                _passrole(
                    "*", {operator: {"iam:PassedToService": "sagemaker.amazonaws.com"}}
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "value",
        [
            "*.bedrock-agentcore.amazonaws.com",
            "*-identity.bedrock-agentcore.amazonaws.com",
            "runtime-identity.*",
            "*.bedrock-agentcore.*",
            "bedrock-agentcore*",
        ],
    )
    def test_a_wildcard_value_covering_an_agentcore_principal_is_in_scope(self, value):
        """A condition value that COVERS an AgentCore principal must FAIL.

        The policy allows no other AgentCore action, so the pin is the only thing that can put the
        statement in scope -- and each of these PASSed. The value was probed as a pattern against
        one base principal, and a regex asked whether it IS a family member; neither asked whether
        it COVERS one. So a wildcard reaching runtime-identity.bedrock-agentcore.amazonaws.com read
        as a pin to some other service and the statement left scope.

        The severity is in the ordering: the narrower literal FAILs and the no-condition case FAILs,
        so BROADENING the grant flipped the verdict to clean. That is the direction that never
        self-corrects, because a PASS is filed and nobody looks again.
        """
        policy = _policy(
            [_passrole("*", {"StringEquals": {"iam:PassedToService": value}})],
            name="wildcard_principal",
        )
        result = _run([policy])
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Custom Policy wildcard_principal allows iam:PassRole to Bedrock AgentCore on every "
            "role instead of the specific execution roles AgentCore is meant to run as."
        )

    @pytest.mark.parametrize(
        "value",
        [
            "*.sagemaker.amazonaws.com",
            "?.bedrock-agentcore.amazonaws.com",
            "bedrock.amazonaws.com",
        ],
    )
    def test_a_wildcard_value_covering_no_agentcore_principal_stays_out_of_scope(
        self, value
    ):
        """A wildcard that reaches no AgentCore principal must still PASS.

        The guard on the fix above, and the middle row is the one that matters: `?` matches exactly
        one character and no principal has a single-character subdomain, so that value covers
        nothing and reads as a pin elsewhere. Treating any metacharacter as coverage would report
        all three, and `bedrock.amazonaws.com` shows the prefix test is not a substring test.
        """
        policy = _policy(
            [_passrole("*", {"StringEquals": {"iam:PassedToService": value}})]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize("operator", ["ArnLike", "ArnEquals", "ArnLikeIfExists"])
    def test_an_arn_operator_on_a_string_key_is_not_read_as_a_pin(self, operator):
        """An ARN operator on iam:PassedToService must not be read as naming a service.

        The allow-list carries only the string operators, deliberately: iam:PassedToService is
        string-typed and holds a service principal, and AWS documents it as working with the string
        operators, so an ARN operator on it cannot compare meaningfully. That makes this list
        shorter than the trust check's, which needs the ARN spellings because aws:SourceArn is
        ARN-typed -- and a shorter list reads as an oversight unless something asserts it.

        The value here names ANOTHER service, so admitting these operators would take the statement
        out of scope and PASS it. Unread, the statement reaches the no-pin path and the document
        decides: FAIL beside the AgentCore action, by the same route as carrying no condition at all.
        """
        policy = _policy(
            [
                _passrole(
                    "*", {operator: {"iam:PassedToService": "sagemaker.amazonaws.com"}}
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "guard",
        ["false", False],
        ids=["guard-as-string", "guard-as-json-boolean"],
    )
    @pytest.mark.parametrize(
        "operator",
        [
            "StringEqualsIfExists",
            "StringLikeIfExists",
            "ForAllValues:StringEquals",
            "ForAllValues:StringEqualsIfExists",
        ],
    )
    def test_a_guarded_defeasible_pin_confines_the_service(self, operator, guard):
        """A defeasible pin with a same-key Null:"false" guard must PASS, either spelling.

        The guard forces the key to be present, so the caller cannot reach AgentCore by omitting it
        and the statement really is confined to sagemaker. This rescue was applied to the trust
        check's collector and never here, so every one of these FAILed beside an AgentCore action --
        penalising the spelling AWS prescribes: "You should always include the Null condition
        operator ... with a false value". Adding the guard to a pinned statement made the verdict
        worse, which is the shape that turns hardening into a finding.

        The guard is parametrized over the STRING and the JSON BOOLEAN because IAM stores both and
        hands back what it was given: create_policy with {"Null": {"iam:PassedToService": false}}
        is accepted and get_policy_version returns a Python bool, unconverted. Reading only the
        string left all four operators above FAILing on the hardened spelling. Measured on a
        customer-managed policy, which is this check's own population -- a trust policy normalizes
        the same value to "false", so this surface is the only one where the bool is observable.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    {
                        operator: {"iam:PassedToService": "sagemaker.amazonaws.com"},
                        "Null": {"iam:PassedToService": guard},
                    },
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "condition",
        [
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "bedrock-agentcore.amazonaws.com"
                },
                "Null": {"iam:PassedToService": "false"},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:PassedToService": "true"},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:AssociatedResourceArn": "false"},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:PassedToService": 0},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:PassedToService": True},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:PassedToService": ["true", "false"]},
            },
            {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "sagemaker.amazonaws.com"
                },
                "Null": {"iam:PassedToService": ["false", "true"]},
            },
        ],
        ids=[
            "guard-names-agentcore",
            "guard-demands-absence",
            "guard-on-another-key",
            "guard-is-a-number",
            "guard-is-boolean-true",
            "guard-list-ORs-to-always-true",
            "guard-list-ORs-to-always-true-reversed",
        ],
    )
    def test_the_guard_rescue_requires_the_right_guard(self, condition):
        """The rescue must not fire on any Null block that happens to be present.

        The last two are the sharpest, because they made the check score a WEAKER policy BETTER: values
        inside one condition operator are ORed by IAM, so ["true","false"] means "key absent OR key
        present", which is always true and binds nothing. Reading the list with `any` credited it, so
        adding the word "true" to a guard list turned a FAIL into a PASS. Both orderings are pinned
        because a fix that scanned only the first element would satisfy one and not the other. Measured
        on IAM's own evaluator with the key omitted: `allowed` for both orderings, indistinguishable
        from carrying no Null block, against `implicitDeny` for "false", ["false"] and
        ["false","false"]. And reachable rather than argued: create_policy stores the multi-value list
        and get_policy_version returns it unchanged.

        Seven negatives, each failing for its own reason: the first is guarded but names AgentCore
        so it is in scope on its own terms; `Null: "true"` demands the key be ABSENT, which makes the
        operator vacuous by design rather than rescuing it; and a guard on a different key leaves
        iam:PassedToService omissible. These mirror the trust check's cases, so the two collectors
        are now pinned to one rule in both directions.

        The last two are the controls on reading a JSON boolean, and they exist because crediting a
        guard turns a FAIL into a PASS -- over-recognition is the unsafe direction here. `0` must
        NOT count, and what it pins is the FORMULATION: the tempting `not candidate` or
        `candidate is False` reads 0, "", None and [] as guards, because isinstance(False, int) is
        True in Python and falsiness is not the question being asked. Boolean `True` must not count
        either, for the same reason its string spelling does not -- it demands absence, so it makes the
        operator vacuous rather than rescuing it.

        An earlier version of this docstring cited Access Analyzer as drawing the same boundary. It does
        not: measured, it reports TYPE_MISMATCH_BOOLEAN for "FALSE" and " false ", both of which this
        check CREDITS, as well as for 0, which it does not. The boundary here is the check's own.
        """
        policy = _policy([_passrole("*", condition), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    def test_one_unskippable_operator_confines_the_statement_whatever_sits_beside_it(
        self,
    ):
        """A defeasible operator beside a firm one must not make the statement defeasible.

        Conditions are ANDed, so `StringEquals` alone already holds the request to sagemaker
        whatever the `StringEqualsIfExists` next to it does; the statement is confined and out of
        scope. Every other test here uses ONE operator on the key, so none of them can tell
        `all(defeasible)` from `any(defeasible)`; this mixed fixture is the input that
        distinguishes them. Under `any` the pin would read as
        skippable, the document-wide fallback would pull the statement back in beside the AgentCore
        action, and this would FAIL.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    {
                        "StringEquals": {
                            "iam:PassedToService": "sagemaker.amazonaws.com"
                        },
                        "StringEqualsIfExists": {
                            "iam:PassedToService": "sagemaker.amazonaws.com"
                        },
                    },
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "operator",
        [
            "StringEqualsIfExists",
            "StringLikeIfExists",
            "ForAllValues:StringEquals",
            "ForAllValues:StringEqualsIfExists",
        ],
    )
    def test_a_pin_the_caller_can_skip_does_not_confine_the_service(self, operator):
        """A defeasible pin naming another service must still FAIL beside an AgentCore action.

        It names sagemaker, but the caller reaches AgentCore by omitting the key, so the statement
        is not confined and scope falls to the rest of the policy. This is the same rule the
        pre-existing *IfExists case asserts, extended to the ForAllValues spellings, and it is why
        reading the value is not the same as crediting it as a constraint.
        """
        policy = _policy(
            [
                _passrole(
                    "*", {operator: {"iam:PassedToService": "sagemaker.amazonaws.com"}}
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_role_wildcard_arn_fails(self):
        """An IAM ARN ending in role/* names every role in the account, so it must FAIL."""
        policy = _policy(
            [_passrole(ANY_ROLE_IN_ACCOUNT_ARN), AGENTCORE_ACTION_STATEMENT]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_account_wide_wildcard_arn_fails(self):
        """An IAM ARN whose whole resource field is "*" names every role, so it must FAIL."""
        policy = _policy(
            [_passrole(f"arn:aws:iam::{AWS_ACCOUNT_ID}:*"), AGENTCORE_ACTION_STATEMENT]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_role_prefix_without_slash_fails(self):
        """role* without a slash still matches every role path, so it must FAIL.

        A pattern that looks narrower than role/* is not: the wildcard swallows the separator too.
        """
        policy = _policy(
            [
                _passrole(f"arn:aws:iam::{AWS_ACCOUNT_ID}:role*"),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_named_role_passes(self):
        """PassRole confined to one fully named role, path included, must PASS."""
        policy = _policy(
            [
                _passrole(
                    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/service-role/AgentCoreRuntimeRole",
                    _passed_to(AGENTCORE_PRINCIPAL),
                )
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_service_linked_role_path_passes(self):
        """PassRole confined to a service-linked-role path must PASS.

        Measured live on AWS Config collector policies: the wildcard sits inside a path that
        bounds the role set, so it is not every role.
        """
        policy = _policy(
            [
                _passrole(
                    "arn:aws:iam::*:role/aws-service-role/config.amazonaws.com/*",
                    _passed_to(AGENTCORE_PRINCIPAL),
                )
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_role_path_wildcard_with_name_prefix_passes(self):
        """A wildcard path combined with a name prefix still bounds the role set, so PASS."""
        policy = _policy(
            [
                _passrole(
                    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/*/AgentCore-*",
                    _passed_to(AGENTCORE_PRINCIPAL),
                )
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_multiple_resources_fail_if_any_names_every_role(self):
        """One resource naming every role makes the statement FAIL despite a scoped sibling.

        IAM evaluates each Resource independently, so a narrow entry cannot rescue a broad one.
        """
        policy = _policy(
            [
                _passrole(
                    [EVALUATION_ROLE_PREFIX_ARN, ANY_ROLE_IN_ACCOUNT_ARN],
                    _passed_to(AGENTCORE_PRINCIPAL),
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource",
        [
            f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/?*",
            f"arn:aws:iam::{AWS_ACCOUNT_ID}:*role*",
            "arn:aws:iam::*",
            f"*:aws:iam::{AWS_ACCOUNT_ID}:role/*",
        ],
    )
    def test_a_resource_that_names_every_role_without_being_all_stars_fails(
        self, resource
    ):
        """Every resource that names every role must FAIL, not only a run of asterisks.

        All four PASSed. `role/?*` names every role with at least one character and `*role*` every
        role/... resource there is; `arn:aws:iam::*` has a star spanning the account and resource
        fields, and the last is a wildcarded partition, which the old regex could not express
        because it was anchored on a literal `arn:`. None of these is narrower than `role/*`, which
        FAILed correctly all along.
        """
        policy = _policy([_passrole(resource), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource",
        [
            "arn:aws:iam::555555555555*",
            f"arn:aws:iam::{AWS_ACCOUNT_ID}*",
            "arn:aws-us-gov:iam::*",
            "arn:aws-cn:iam::*",
            "arn:aws-us-gov:*",
            # Four fields with an EMPTY region head, which the region test must not catch: the
            # star spans the region onward, and `?` matches the colon.
            "arn:aws:iam:*",
            "arn:aws:iam:?*",
        ],
    )
    def test_a_truncated_arn_names_every_role_in_any_partition_or_account(
        self, resource
    ):
        """A short starred IAM ARN must FAIL whatever partition or account it names.

        The previous fix matched short ARNs against probes pinned to partition `aws` and account
        123456789012, so those two values became load-bearing in the SHORT branch while the
        six-field branch ignored both. `arn:aws:iam::555555555555*` was therefore read as specific
        while the identical shape in the probe's own account FAILed, and the two non-commercial
        partitions were read as specific because no probe carried them.

        An account PREFIX is what shows no probe corpus could fix this: there is nothing to
        enumerate. Decided structurally now -- a star in the last spelled-out field spans every field
        after it, so the resource name is unbounded and every role is named.
        """
        policy = _policy([_passrole(resource), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "resource",
        [
            f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/?",
            "arn:aws:iam::*:role/AgentCoreEvaluationRole*",
            "arn:aws:iam",
            "arn:aws:iam::role/Prod*",
            # The same shape one colon short, so the literal head lands in the REGION position
            # instead of the account one. Every IAM ARN has an empty region, so each of these
            # matches no role ARN at all -- and each read as naming EVERY role until the region
            # position was tested, drawing a high-severity FAIL on a pattern reaching nothing.
            "arn:aws:iam:role/Prod*",
            "arn:aws:iam:us-east-1*",
            "arn:aws:iam:r?le/Prod*",
            # A resource that is not an IAM ARN at all names no role, so it cannot name every role.
            # Each of these four reaches a different rejection: the partition-prefix and service
            # fields are tested in the short branch and again in the six-field one, and none of the
            # four was exercised before. iam:PassRole on an S3 ARN is nonsense a real policy can
            # still carry, since IAM stores any syntactically valid ARN.
            "xyz:aws:iam:*",
            "arn:aws:s3:*",
            f"xyz:aws:iam::{AWS_ACCOUNT_ID}:role/*",
            "arn:aws:s3:::amzn-s3-demo-bucket/*",
        ],
    )
    def test_a_resource_that_names_a_bounded_set_of_roles_passes(self, resource):
        """A resource covering some roles but not all of them must still PASS.

        The guard on the fix above, and the reason the rule is not "contains a metacharacter":
        `role/?` matches exactly one character so it names single-character roles only, the
        prefix form is the scope AWS's own AgentCore Evaluations reference policy uses, and
        `arn:aws:iam` carries no star so it matches no ARN at all. Widening the fix to catch
        `role/?*` by treating any metacharacter as unbounded would report all three.

        The last three are the four-field spellings. `arn:aws:iam::role/Prod*` above puts
        `role/Prod` in the ACCOUNT position, where the digits test rejects it; one colon fewer
        puts it in the REGION position, which went untested. A region literal is included because
        it is the shape an operator plausibly writes, and IAM has no region either way.
        """
        policy = _policy([_passrole(resource), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "resource",
        [
            f"arn:aws:iam:us-east-1:{AWS_ACCOUNT_ID}:role/*",
            f"arn:aws:iam:?:{AWS_ACCOUNT_ID}:role/*",
            f"arn:aws:iam:us-east-1:{AWS_ACCOUNT_ID}:role/?*",
            "arn:aws:iam::12345:role/*",
            "arn:aws:iam:::role/*",
            "arn:aws:iam::?????:role/*",
        ],
    )
    def test_a_six_field_arn_that_names_no_role_passes(self, resource):
        """A fully spelled-out ARN naming no role must PASS, as the short spellings already do.

        The six-field branch applied neither the region test nor the account one, so every resource
        here drew a high-severity privilege-escalation FAIL on a pattern matching no role ARN at
        all -- the same defect the four- and five-field branches had already been fixed for,
        surviving in the branch that was not re-read.

        Every IAM ARN has an EMPTY region, so `us-east-1` in that position names nothing, and `?`
        names nothing either: unlike the short branch, this field is delimited on both sides, so
        there is no colon for `?` to match and it must consume one character of a region that has
        none. An account is twelve digits, so `12345`, the empty field and five `?` each name no
        account however the resource field is spelled.
        """
        policy = _policy([_passrole(resource), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize(
        "resource",
        [
            f"arn:aws:iam:*:{AWS_ACCOUNT_ID}:role/*",
            "arn:aws:iam::1234567890*:role/*",
            ANY_ROLE_IN_ACCOUNT_ARN,
            "arn:aws:iam::????????????:role/*",
            "arn:aws:iam::12345678901?:role/*",
            "arn:aws:iam:*:*:role/*",
        ],
    )
    def test_a_six_field_arn_that_names_every_role_still_fails(self, resource):
        """The guard on the fix above: the region and account tests must reject only unnameable
        shapes, never a wildcard that spans a real region or account.

        `*` matches the empty region IAM ARNs carry, an account prefix followed by a star spans
        every account sharing it, and twelve `?` spans every account there is -- one `?` short of
        twelve names none, which is the pair that pins the width rule rather than assuming it.
        `ANY_ROLE_IN_ACCOUNT_ARN` is here because it FAILed correctly before the fix and must go on
        doing so: it is the shape the check exists to report.
        """
        policy = _policy([_passrole(resource), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    def test_iam_service_wildcard_action_fails(self):
        """iam:* covers iam:PassRole, so the statement must FAIL."""
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL), action="iam:*")]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_iam_action_prefix_wildcard_fails(self):
        """iam:Pass* reaches iam:PassRole, so the statement must FAIL."""
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL), action=["iam:Pass*"])]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_service_in_the_agentcore_action_brings_the_policy_into_scope(
        self,
    ):
        """`bedrock-*:CreateAgentRuntime` is AgentCore reach, so an unpinned PassRole beside it FAILs.

        This is the consequential half of the same wildcard defect: `bedrock-*` is a plausible thing
        to write, since one prefix covers bedrock and bedrock-agentcore together. A literal
        comparison read it as no AgentCore reach, which left the unpinned PassRole statement out of
        scope entirely and the policy PASSed.
        """
        policy = _policy(
            [
                _passrole("*"),
                {
                    "Effect": "Allow",
                    "Action": ["bedrock-*:CreateAgentRuntime"],
                    "Resource": "*",
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_wildcard_service_in_the_passrole_action_fails(self):
        """`*:PassRole` names every service, IAM among them, so it covers iam:PassRole.

        Legal but implausible on its own; fixed for consistency with the AgentCore-reach test above,
        since both read a service field and one line each removes a known false PASS.
        """
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL), action="*:PassRole")]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_unrelated_service_in_the_action_stays_out_of_scope(self):
        """An unrelated service in either action field must not create reach or coverage, so PASS.

        The guard against the two fixes above over-reaching: `s3` is matched as a pattern and must
        match neither `iam` nor `bedrock-agentcore`.
        """
        policy = _policy(
            [
                _passrole("*", action="s3:GetObject"),
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_bare_action_wildcard_is_left_to_admin_checks(self):
        """A bare Action "*" is left to the administrative-privileges checks, so PASS here.

        Reporting it would duplicate check_admin_access rather than add a claim.
        """
        policy = _policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        assert _run([policy])[0].status == "PASS"

    def test_bare_action_wildcard_is_not_the_agentcore_evidence(self):
        """A bare Action "*" is not evidence that the policy reaches AgentCore.

        Were it counted, every administrator policy would be pulled into this check through the
        AgentCore-reach test rather than through a real AgentCore grant.
        """
        policy = _policy(
            [
                _passrole("*"),
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::my-bucket",
                },
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_other_iam_action_is_not_passrole(self):
        """An IAM action that is not PassRole must not put the statement in scope."""
        policy = _policy(
            [_passrole("*", action="iam:GetRole"), AGENTCORE_ACTION_STATEMENT]
        )
        assert _run([policy])[0].status == "PASS"

    def test_passed_to_service_wildcard_is_in_scope(self):
        """iam:PassedToService pinned to "*" pins nothing, so the statement is in scope and FAILs."""
        policy = _policy([_passrole("*", _passed_to("*"))])
        assert _run([policy])[0].status == "FAIL"

    def test_passed_to_service_subdomain_principal_is_in_scope(self):
        """A subdomain principal in the AgentCore family is still AgentCore, so it FAILs.

        runtime-identity.bedrock-agentcore.amazonaws.com reaches IAM as AgentCore does, so
        matching only the base principal would let the subdomain form through.
        """
        policy = _policy(
            [
                _passrole(
                    "*", _passed_to("runtime-identity.bedrock-agentcore.amazonaws.com")
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("browser-tool.bedrock-agentcore.amazonaws.com", "FAIL"),
            ("code-interpreter.bedrock-agentcore.amazonaws.com", "FAIL"),
            ("browser-tool.bedrock-agentcore.example.com", "PASS"),
        ],
        ids=["browser-tool", "code-interpreter", "wrong-suffix"],
    )
    def test_a_subdomain_principal_no_probe_enumerates_is_in_scope(
        self, value, expected
    ):
        """A literal subdomain principal outside the probe list must still FAIL.

        The third row is the one that pins ANCHORING rather than membership: it differs from the
        first in one field, so a family regex that lost its trailing `$` would return the same
        verdict for both and only this pair can tell them apart. The first two rows are positives
        that no probe enumerates, so together the parameters exercise both mechanisms.

        This is what the family regex is for, and the test above can no longer show it: the
        principal it uses became one of AGENTCORE_PRINCIPAL_PROBES when coverage matching was
        added, so the probes alone now carry it and deleting the regex changes nothing it asserts.

        `browser-tool.` is not enumerated anywhere, so with the regex gone this value matches no
        probe -- a literal pattern matches only itself -- and the statement would leave scope. The
        two mechanisms answer different questions and each needs one input only it can decide.
        """
        policy = _policy([_passrole("*", _passed_to(value))])
        assert _run([policy])[0].status == expected

    def test_bare_action_wildcard_pair_is_left_to_admin_checks(self):
        """`Action: "*:*"` must PASS: it is check_admin_access's finding, not this one.

        The only bare-wildcard fixture was `"*"`, which the `separator != ":"` clause alone
        satisfies, so the `service == "*" and operation == "*"` clause was load-bearing with zero
        coverage -- deleting it left every test green while flipping this policy to FAIL.
        """
        policy = _policy(
            [_passrole("*", _passed_to(AGENTCORE_PRINCIPAL), action="*:*")]
        )
        assert _run([policy])[0].status == "PASS"

    def test_an_account_head_of_question_marks_still_names_every_role(self):
        """`arn:aws:iam::?*` names every role, so it must FAIL.

        The account head is "?", which `.replace("?", "")` reduces to empty and therefore accepts as
        account-shaped; the star then spans every field after it. Dropping that strip judged the head
        non-numeric and declared the pattern specific, with all 87 tests still green.
        """
        policy = _policy([_passrole("arn:aws:iam::?*"), AGENTCORE_ACTION_STATEMENT])
        assert _run([policy])[0].status == "FAIL"

    def test_a_naming_convention_scope_is_not_every_role(self):
        """`role/*-*` is a naming convention, not every role, so it must PASS.

        It matches the 64-character probe but not "role/a", which is exactly what the shortest-name
        probe exists to catch. Dropping that probe left the suite green and reported this scope as
        "every role".
        """
        policy = _policy(
            [
                _passrole(f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/*-*"),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_passed_to_service_list_with_one_agentcore_value_is_in_scope(self):
        """A PassedToService list containing one AgentCore value is in scope and FAILs.

        The other value being a different service must not rescue it: any one value that can name
        AgentCore is sufficient.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    _passed_to(["sagemaker.amazonaws.com", AGENTCORE_PRINCIPAL]),
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_negated_operator_does_not_pin_the_service(self):
        """StringNotEquals inverts the match, so it pins the statement to no service at all.

        Scope then falls to the rest of the policy, which allows an AgentCore action, so it FAILs.
        Crediting a negated operator as a pin would clear a statement that confines nothing.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    {
                        "StringNotEquals": {
                            "iam:PassedToService": "sagemaker.amazonaws.com"
                        }
                    },
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_if_exists_operator_does_not_pin_the_service(self):
        """An *IfExists operator is skipped when the caller omits the key, so it pins nothing.

        Scope falls to the rest of the policy and the statement FAILs, for the same reason as the
        negated operator above.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    {
                        "StringEqualsIfExists": {
                            "iam:PassedToService": "sagemaker.amazonaws.com"
                        }
                    },
                ),
                AGENTCORE_ACTION_STATEMENT,
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_associated_resource_arn_does_not_bound_the_role_set(self):
        """iam:AssociatedResourceArn bounds the target resource, not the set of passable roles.

        So a statement carrying it alongside Resource "*" still hands AgentCore every role and
        must FAIL: the two conditions constrain different things.
        """
        policy = _policy(
            [
                _passrole(
                    "*",
                    {
                        "StringEquals": {"iam:PassedToService": AGENTCORE_PRINCIPAL},
                        "ArnLike": {
                            "iam:AssociatedResourceArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/*"
                        },
                    },
                )
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_not_resource_fails(self):
        """A statement using NotResource leaves every role outside the exclusion passable, so FAIL."""
        statement = _passrole(None, _passed_to(AGENTCORE_PRINCIPAL))
        statement["NotResource"] = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/BreakGlass"
        assert _run([_policy([statement])])[0].status == "FAIL"

    def test_statement_without_resource_or_not_resource_passes(self):
        """A statement naming neither Resource nor NotResource grants no resource, so PASS."""
        policy = _policy([_passrole(None, _passed_to(AGENTCORE_PRINCIPAL))])
        assert _run([policy])[0].status == "PASS"

    def test_unconditional_deny_of_passrole_everywhere_clears_the_finding(self):
        """An unconditional Deny of iam:PassRole on "*" removes the permission, so PASS."""
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "PASS"

    @pytest.mark.parametrize("deny_action", ["*", "*:*"])
    def test_a_deny_of_every_action_clears_the_finding(self, deny_action):
        """A Deny of EVERY action on "*" removes iam:PassRole, so the policy must PASS.

        Both spellings reported FAIL on a policy granting no PassRole at all. The Deny side reused
        the Allow side's reader, which skips a bare "*" and "*:*" so this check does not duplicate
        the administrative-privileges checks; on the Deny side that exclusion inverts and the
        broadest possible Deny credited nothing. The Allow-side guard is deliberately untouched,
        since relaxing it would reverse that settled decision.
        """
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {"Effect": "Deny", "Action": deny_action, "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_a_deny_of_every_action_in_another_service_does_not_clear_the_finding(self):
        """The guard on the fix above: `s3:*` removes no iam:PassRole, so this must still FAIL."""
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_listing_the_wildcard_among_other_resources_clears_the_finding(self):
        """A Deny whose Resource list contains "*" denies PassRole everywhere.

        _denies_passrole_everywhere tests the list with any(), not all(): IAM evaluates each
        Resource independently, so one "*" entry is sufficient. Under all() this policy stops
        clearing the finding and the check reports a false FAIL. Every other Deny fixture
        supplies a single Resource string, so nothing else distinguishes the two operators.
        """
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": ["*", ANY_ROLE_IN_ACCOUNT_ARN],
                },
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_condition_block_that_is_not_a_mapping_is_skipped(self):
        """A Condition operator whose block is not a mapping must be stepped over.

        The guard is `not isinstance(operator, str) or not isinstance(block, dict)`. Under
        `and` it only skips when *both* are malformed, so a valid operator with a string
        block reaches `block.items()` and raises AttributeError -- which the framework
        swallows, turning the check into one that silently reports nothing. Policy documents
        come from the account, so a malformed block is account input rather than a
        hypothetical.
        """
        policy = _policy([_passrole("*", {"StringEquals": "iam:PassedToService"})])
        result = _run([policy])
        # What this pins is that the check still REACHES a verdict. The malformed block
        # yields no iam:PassedToService value, so no statement is a relevant AgentCore
        # grant and the policy passes. Under `and` the guard stops firing, block.items()
        # raises AttributeError, the framework swallows it and the check reports nothing at
        # all -- so the finding count is the assertion that matters here.
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_conditional_deny_does_not_clear_the_finding(self):
        """A CONDITIONAL Deny must not clear the finding: it only bites when the condition holds.

        The Allow still stands for every request outside the condition, so the capability remains.
        """
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "agents"}},
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_scoped_to_one_role_does_not_clear_the_finding(self):
        """A Deny naming one role does not answer an Allow that reaches every other one."""
        policy = _policy(
            [
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
                {
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/BreakGlass",
                },
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_deny_only_policy_passes(self):
        """A policy containing only a Deny grants nothing, so it must PASS."""
        policy = _policy(
            [{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]
        )
        assert _run([policy])[0].status == "PASS"

    def test_conditional_deny_only_policy_passes(self):
        """A conditional Deny alone still grants nothing, so it must PASS.

        Reading Effect is what stops the statement being treated as though it allowed PassRole.
        """
        policy = _policy(
            [
                {
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": AGENTCORE_PRINCIPAL}
                    },
                }
            ]
        )
        assert _run([policy])[0].status == "PASS"

    def test_single_statement_dict_is_evaluated(self):
        """A Statement given as a single dict rather than a list is still evaluated.

        IAM accepts both shapes, so a check reading only lists would silently skip the policy.
        """
        policy = _policy(None)
        policy.document = {
            "Version": "2012-10-17",
            "Statement": _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
        }
        assert _run([policy])[0].status == "FAIL"

    def test_malformed_statements_do_not_raise(self):
        """Malformed statements must not raise, and must not mask the real grant beside them.

        A bare string, non-string actions, an action with no colon and a non-mapping Condition all
        coexist with one genuine unbounded grant, so the FAIL proves the parser survived rather
        than short-circuited.
        """
        policy = _policy(
            [
                "not-a-statement",
                {"Effect": "Allow", "Action": [None, 7], "Resource": [None]},
                {"Effect": "Allow", "Action": "iam", "Resource": "*"},
                {"Effect": "Allow", "Action": "iam:PassRole", "Condition": "broken"},
                _passrole("*", _passed_to(AGENTCORE_PRINCIPAL)),
            ]
        )
        assert _run([policy])[0].status == "FAIL"

    def test_every_policy_gets_one_finding(self):
        """Three policies get one report each, judged on their own document.

        FAIL, PASS and MANUAL from one run, so a check reporting only the first policy or carrying
        a verdict between them would not produce this mapping.
        """
        policies = [
            _policy([_passrole("*", _passed_to(AGENTCORE_PRINCIPAL))], name="broad"),
            _policy(
                [
                    _passrole(
                        EVALUATION_ROLE_PREFIX_ARN, _passed_to(AGENTCORE_PRINCIPAL)
                    )
                ],
                name="scoped",
            ),
            _policy([], name="unreadable", document_present=False),
        ]
        result = _run(policies)
        assert {report.resource_id: report.status for report in result} == {
            "broad": "FAIL",
            "scoped": "PASS",
            "unreadable": "MANUAL",
        }


class Test_iam_policy_passrole_to_bedrock_agentcore_restricted_notaction:
    """NotAction under Effect Allow is IAM-valid and grants everything it does not list."""

    def test_notaction_allow_statement_is_manual(self):
        """The check reads only Action, so a NotAction statement looked like no grant at all.

        `{"Effect": "Allow", "NotAction": ["s3:*"], "Resource": "*"}` grants every action
        except S3 -- including the ones this check exists to find -- while carrying no Action
        key. IAM Access Analyzer ValidatePolicy accepts the shape, so it is reachable in a
        stored policy. Inverting NotAction correctly means resolving it against the whole
        action namespace and its interaction with Resource and NotResource, which is more
        than this check can claim, so it reports the policy as unevaluated instead.
        """
        policy = _policy(
            [{"Effect": "Allow", "NotAction": ["s3:*"], "Resource": "*"}],
            name="notaction-policy",
        )
        result = _run([policy])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "NotAction" in result[0].status_extended
