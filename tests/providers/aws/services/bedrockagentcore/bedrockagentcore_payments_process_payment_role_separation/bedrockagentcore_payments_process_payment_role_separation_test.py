from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ROLE_NAME = "test-payment-role"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_NAME}"
PAYMENT_MANAGER_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:payment-manager/example"
MANAGER_PREFIX = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    ":payment-manager"
)
BOTH_ACTION_NAMES = [
    "bedrock-agentcore:CreatePaymentSession",
    "bedrock-agentcore:ProcessPayment",
]


def _doc(actions, effect="Allow", resource=PAYMENT_MANAGER_ARN):
    """Build a single-statement policy document."""
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": actions, "Resource": resource}],
    }


def _not_action_doc(not_actions, resource="*"):
    """Build a single-statement Allow document that uses NotAction."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": not_actions, "Resource": resource}
        ],
    }


SESSION_ONLY_DOC = _doc(["bedrock-agentcore:CreatePaymentSession"])
PROCESS_ONLY_DOC = _doc(["bedrock-agentcore:ProcessPayment"])
BOTH_ACTIONS_DOC = _doc(
    [
        "bedrock-agentcore:CreatePaymentSession",
        "bedrock-agentcore:ProcessPayment",
    ]
)
SERVICE_WILDCARD_DOC = _doc("bedrock-agentcore:*")
ADMIN_WILDCARD_DOC = _doc("*", resource="*")
# bedrock-agentcore:Process* reaches ProcessPayment but not CreatePaymentSession.
PROCESS_PREFIX_WILDCARD_DOC = _doc("bedrock-agentcore:Process*")
# Casing must not change the outcome; IAM matches action names case-insensitively.
ODD_CASE_BOTH_DOC = _doc(
    ["BEDROCK-AGENTCORE:createpaymentsession", "bedrock-agentcore:PROCESSPAYMENT"]
)
DENY_PROCESS_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:CreatePaymentSession",
            "Resource": PAYMENT_MANAGER_ARN,
        },
        {
            "Effect": "Deny",
            "Action": "bedrock-agentcore:ProcessPayment",
            "Resource": "*",
        },
    ],
}
UNRELATED_DOC = _doc("bedrock-agentcore:InvokeAgentRuntime")
# "*:*" reaches both payment actions just as "*" does.
SERVICE_AND_ACTION_WILDCARD_DOC = _doc("*:*", resource="*")
# An intra-action glob reaches both actions: CreatePaymentSession and
# ProcessPayment both contain "Payment".
INFIX_GLOB_DOC = _doc("bedrock-agentcore:*Payment*")
# A glob need not be a suffix to match; Create*Session reaches
# CreatePaymentSession.
INFIX_GLOB_PLUS_PROCESS_DOC = _doc(
    ["bedrock-agentcore:Create*Session", "bedrock-agentcore:ProcessPayment"]
)
# An Allow with NotAction grants every action it does not exclude, including
# both payment actions.
NOT_ACTION_UNRELATED_DOC = _not_action_doc("s3:DeleteBucket")
# Excluding ProcessPayment leaves only the session half granted.
NOT_ACTION_EXCLUDING_PROCESS_DOC = _not_action_doc("bedrock-agentcore:ProcessPayment")
# A valid statement beside a malformed one. get_effective_actions expects dicts, so the
# collector filters non-dicts out; the filter fires on `not all(...)`, and under `not any(...)`
# it only fires when NOTHING is a dict, leaving the garbage in place.
MIXED_STATEMENT_TYPES_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock-agentcore:CreatePaymentSession",
                "bedrock-agentcore:ProcessPayment",
            ],
            "Resource": "*",
        },
        "this-is-not-a-statement",
    ],
}
# A Resource pattern longer than CPython's default recursion limit can absorb. The pattern
# relations used to recurse once per character, so comparing this pattern with itself raised
# RecursionError -- measured at 993 characters for an all-literal pattern and 685 for one
# carrying `*` every other character. Both fit inside every IAM policy quota: a role's inline
# policies may total 10,240 characters and a customer managed policy 6,144, and IAM documents no
# maximum length for a single Resource string. RecursionError is caught by the check executor,
# which then reports zero findings -- so the FAIL below was silently dropped rather than raised.
LONG_MANAGER_ARN = f"{MANAGER_PREFIX}/prod-checkout-{'x' * 1000}*"

BARE_DICT_BOTH_DOC = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": [
            "bedrock-agentcore:CreatePaymentSession",
            "bedrock-agentcore:ProcessPayment",
        ],
        "Resource": PAYMENT_MANAGER_ARN,
    },
}


# Distinguishes "caller passed nothing" from "caller passed None". Without it the helper
# coalesced None to [], which left the unreadable-inventory branch unreachable from the tests,
# so nothing here would have caught that branch reporting PASS instead of MANUAL.
_UNSET = object()


class _Role:
    """Minimal stand-in for the IAM service Role model."""

    def __init__(self, attached_policies=None, inline_policies=None, name=ROLE_NAME):
        self.name = name
        self.arn = ROLE_ARN
        self.attached_policies = attached_policies or []
        self.inline_policies = inline_policies or []


class _Policy:
    """Minimal stand-in for the IAM service Policy model."""

    def __init__(self, document):
        self.document = document


class Test_bedrockagentcore_payments_process_payment_role_separation:
    """Unit tests for the AgentCore payment role separation check."""

    def _run(self, roles=_UNSET, policies=None):
        """Import the check under a stub IAM client and execute."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        iam_client = mock.MagicMock()
        iam_client.roles = [] if roles is _UNSET else roles
        iam_client.policies = policies if policies is not None else {}
        iam_client.region = AWS_REGION_US_EAST_1

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_payments_process_payment_role_separation.bedrockagentcore_payments_process_payment_role_separation.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_payments_process_payment_role_separation.bedrockagentcore_payments_process_payment_role_separation import (
                bedrockagentcore_payments_process_payment_role_separation,
            )

            return bedrockagentcore_payments_process_payment_role_separation().execute()

    @mock_aws
    def test_no_resources(self):
        """No roles means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock_aws
    def test_roles_absent_from_inventory(self):
        """An unreadable IAM inventory is MANUAL, not an account with no roles.

        ListRoles being denied leaves the inventory unknown. Reporting nothing would
        read as a clean account, so the check emits one account-level MANUAL.
        """
        result = self._run(roles=None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "IAM roles could not be listed, so this check could not be evaluated; verify manually that no role allows both payment actions."
        )

    @mock_aws
    def test_role_without_payment_actions_is_skipped(self):
        """A role granting neither payment action is not this check's business."""
        result = self._run(
            roles=[_Role(inline_policies=["unrelated"])],
            policies={f"{ROLE_ARN}:policy/unrelated": _Policy(UNRELATED_DOC)},
        )
        assert result == []

    @mock_aws
    def test_create_payment_session_only_passes(self):
        """A role that only opens sessions cannot execute the payment."""
        result = self._run(
            roles=[_Role(inline_policies=["sessiononly"])],
            policies={f"{ROLE_ARN}:policy/sessiononly": _Policy(SESSION_ONLY_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "CreatePaymentSession" in result[0].status_extended
        assert result[0].resource_id == ROLE_NAME
        assert result[0].resource_arn == ROLE_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_process_payment_only_passes(self):
        """A role that only executes payments cannot set their terms."""
        result = self._run(
            roles=[_Role(inline_policies=["processonly"])],
            policies={f"{ROLE_ARN}:policy/processonly": _Policy(PROCESS_ONLY_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "ProcessPayment" in result[0].status_extended

    @mock_aws
    def test_process_prefix_wildcard_only_passes(self):
        """bedrock-agentcore:Process* reaches only one of the two actions."""
        result = self._run(
            roles=[_Role(inline_policies=["processprefix"])],
            policies={
                f"{ROLE_ARN}:policy/processprefix": _Policy(PROCESS_PREFIX_WILDCARD_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "ProcessPayment" in result[0].status_extended

    @mock_aws
    def test_deny_on_process_payment_passes(self):
        """A Deny on ProcessPayment does not count as granting it."""
        result = self._run(
            roles=[_Role(inline_policies=["denyprocess"])],
            policies={f"{ROLE_ARN}:policy/denyprocess": _Policy(DENY_PROCESS_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_both_actions_in_one_document_fails(self):
        """One role holding both halves completes a transaction unreviewed."""
        result = self._run(
            roles=[_Role(inline_policies=["both"])],
            policies={f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "CreatePaymentSession" in result[0].status_extended
        assert "ProcessPayment" in result[0].status_extended
        assert "end-to-end" in result[0].status_extended

    @mock_aws
    def test_unresolvable_managed_policy_is_named_not_arned(self):
        """The finding names the policy, not its ARN.

        `policy_name = policy.get("PolicyName") or policy_arn` -- under `and` the fallback
        yields the ARN whenever PolicyName is present, and the finding sends a reader to an
        ARN instead of the policy they can look up. Asserting the name as a bare substring
        cannot catch that, because the ARN ends with the same name, so the assertion is on
        the exact rendered phrase plus the absence of any ARN.
        """
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {
                            "PolicyArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/example-process-policy",
                            "PolicyName": "example-process-policy",
                        }
                    ]
                )
            ],
            policies={},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "managed policy example-process-policy" in result[0].status_extended
        assert "arn:aws:iam::" not in result[0].status_extended

    @mock_aws
    def test_both_actions_across_two_policies_fails(self):
        """Effective permissions are the union of every attached policy."""
        result = self._run(
            roles=[
                _Role(
                    inline_policies=["sessiononly"],
                    attached_policies=[
                        {
                            "PolicyArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/example-process-policy",
                            "PolicyName": "example-process-policy",
                        }
                    ],
                )
            ],
            policies={
                f"{ROLE_ARN}:policy/sessiononly": _Policy(SESSION_ONLY_DOC),
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/example-process-policy": _Policy(
                    PROCESS_ONLY_DOC
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_service_wildcard_grants_both_and_fails(self):
        """bedrock-agentcore:* covers both payment actions."""
        result = self._run(
            roles=[_Role(inline_policies=["servicewildcard"])],
            policies={
                f"{ROLE_ARN}:policy/servicewildcard": _Policy(SERVICE_WILDCARD_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_admin_wildcard_grants_both_and_fails(self):
        """Action "*" grants both payment actions too."""
        result = self._run(
            roles=[_Role(inline_policies=["admin"])],
            policies={f"{ROLE_ARN}:policy/admin": _Policy(ADMIN_WILDCARD_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_service_and_action_wildcard_grants_both_and_fails(self):
        """Action "*:*" reaches both payment actions just as "*" does."""
        result = self._run(
            roles=[_Role(inline_policies=["starstar"])],
            policies={
                f"{ROLE_ARN}:policy/starstar": _Policy(SERVICE_AND_ACTION_WILDCARD_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_infix_glob_grants_both_and_fails(self):
        """bedrock-agentcore:*Payment* reaches both halves of the flow."""
        result = self._run(
            roles=[_Role(inline_policies=["infix"])],
            policies={f"{ROLE_ARN}:policy/infix": _Policy(INFIX_GLOB_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_glob_in_middle_of_action_name_fails(self):
        """A wildcard need not be a suffix: Create*Session reaches CreatePaymentSession."""
        result = self._run(
            roles=[_Role(inline_policies=["middle"])],
            policies={
                f"{ROLE_ARN}:policy/middle": _Policy(INFIX_GLOB_PLUS_PROCESS_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_not_action_excluding_unrelated_action_fails(self):
        """An Allow with NotAction grants both payment actions it does not exclude."""
        result = self._run(
            roles=[_Role(inline_policies=["notaction"])],
            policies={
                f"{ROLE_ARN}:policy/notaction": _Policy(NOT_ACTION_UNRELATED_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_not_action_excluding_process_payment_passes(self):
        """Excluding ProcessPayment leaves only the session half, which is compliant."""
        result = self._run(
            roles=[_Role(inline_policies=["excluded"])],
            policies={
                f"{ROLE_ARN}:policy/excluded": _Policy(NOT_ACTION_EXCLUDING_PROCESS_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "CreatePaymentSession" in result[0].status_extended

    @mock_aws
    def test_action_matching_is_case_insensitive(self):
        """IAM matches action names case-insensitively, so casing must still FAIL."""
        result = self._run(
            roles=[_Role(inline_policies=["oddcase"])],
            policies={f"{ROLE_ARN}:policy/oddcase": _Policy(ODD_CASE_BOTH_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_malformed_statement_beside_a_valid_one_is_filtered_not_fatal(self):
        """A non-dict statement must be dropped, leaving the valid one evaluated.

        The filter fires on `not all(isinstance(statement, dict) ...)`. Under
        `not any(...)` it only fires when no statement is a dict at all, so this document
        reaches get_effective_actions with a bare string in the list, raises, and the
        framework swallows it into a check that reports nothing. Policy documents come from
        the account, so a malformed statement is account input rather than a hypothetical.
        """
        result = self._run(
            roles=[_Role(inline_policies=["mixedtypes"])],
            policies={
                f"{ROLE_ARN}:policy/mixedtypes": _Policy(MIXED_STATEMENT_TYPES_DOC)
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_statement_as_bare_dict_is_normalised(self):
        """A dict Statement must be evaluated, not skipped."""
        result = self._run(
            roles=[_Role(inline_policies=["baredict"])],
            policies={f"{ROLE_ARN}:policy/baredict": _Policy(BARE_DICT_BOTH_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_unresolvable_policy_document_is_manual_not_pass(self):
        """The unread policy could hold the other half, so this must not PASS."""
        result = self._run(
            roles=[_Role(inline_policies=["sessiononly", "missing"])],
            policies={f"{ROLE_ARN}:policy/sessiononly": _Policy(SESSION_ONLY_DOC)},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended
        assert "inline policy missing" in result[0].status_extended

    @mock_aws
    def test_a_deny_in_another_policy_removes_the_second_payment_action(self):
        """Separation of duties is a question about the ROLE, so Deny must span its policies.

        This is the case the check used to get wrong. It expanded each document separately and
        unioned the results, so a role allowing both actions in one policy stayed a FAIL even when a
        second policy explicitly denied ProcessPayment -- and IAM would refuse that call, so the role
        cannot in fact complete a payment end to end. The statements are aggregated before
        get_effective_actions runs, which is what lets its Deny subtraction see the other document.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both", "deny-process"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
                f"{ROLE_ARN}:policy/deny-process": _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], effect="Deny")
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a Deny of ProcessPayment in a sibling policy leaves the role unable to execute a "
            f"payment; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_the_two_actions_split_across_policies_still_fail(self):
        """The negative control: aggregation must not hide a genuine violation.

        One policy grants CreatePaymentSession and another grants ProcessPayment. Neither document
        alone violates separation of duties, so a per-document reading would report PASS -- the
        mirror image of the bug above, and the reason aggregation is the correct fix rather than a
        looser one.
        """
        result = self._run(
            roles=[_Role(inline_policies=["session", "process"])],
            policies={
                f"{ROLE_ARN}:policy/session": _Policy(SESSION_ONLY_DOC),
                f"{ROLE_ARN}:policy/process": _Policy(PROCESS_ONLY_DOC),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "one role holding each half across two policies completes a payment end to end; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_deny_spans_attached_and_inline_policies(self):
        """The aggregation must cover both policy kinds, not just inline ones."""
        managed_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/deny-process"
        result = self._run(
            roles=[
                _Role(
                    attached_policies=[
                        {"PolicyArn": managed_arn, "PolicyName": "deny-process"}
                    ],
                    inline_policies=["both"],
                )
            ],
            policies={
                managed_arn: _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], effect="Deny")
                ),
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_a_deny_scoped_to_another_payment_manager_does_not_excuse_the_role(self):
        """A narrow Deny must not cancel a broad Allow — that would be a false PASS.

        Both payment actions take a REQUIRED `payment-manager` resource type per the
        service-authorization reference, so a resource-scoped Deny is the normal shape rather than an
        exotic one. `get_effective_actions` reads only Effect/Action/NotAction, so once a role's
        statements are aggregated a `Deny ProcessPayment on manager B` cancelled the `Allow` covering
        manager A and the role reported PASS — while still able to create and execute a payment
        end to end on A.

        Explicit Deny still wins where it bites; it is no longer allowed to hide a capability it does
        not actually reach.
        """
        other_manager = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-b"
        )
        result = self._run(
            roles=[_Role(inline_policies=["both", "deny-other-manager"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
                f"{ROLE_ARN}:policy/deny-other-manager": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=other_manager,
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny scoped to a different payment manager leaves the role able to complete a "
            f"payment on the one it is allowed; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_conditional_deny_does_not_excuse_the_role(self):
        """A Deny carrying a Condition may not apply, so it must not suppress the finding.

        This errs towards over-reporting on purpose: a Condition that always holds makes this a false
        FAIL. For a separation-of-duties finding a false FAIL is survivable and a false PASS is not.
        """
        denied = _doc(["bedrock-agentcore:ProcessPayment"], effect="Deny", resource="*")
        denied["Statement"][0]["Condition"] = {
            "StringEquals": {"aws:ResourceTag/env": "prod"}
        }
        result = self._run(
            roles=[_Role(inline_policies=["both", "deny-when-prod"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
                f"{ROLE_ARN}:policy/deny-when-prod": _Policy(denied),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_an_unconditional_wildcard_deny_still_wins(self):
        """The control that keeps IAM semantics intact: a Deny that cannot fail to apply subtracts."""
        result = self._run(
            roles=[_Role(inline_policies=["both", "deny-all-resources"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
                f"{ROLE_ARN}:policy/deny-all-resources": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource="*",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "an unconditional Deny on every resource does remove the action; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_the_two_actions_on_disjoint_managers_is_not_a_violation(self):
        """Each half on a DIFFERENT payment manager cannot complete a payment on either.

        Both actions require a `payment-manager` resource, so a session opened on manager A can only
        be processed on manager A. A role allowed to open sessions on A and to process payments on B
        therefore holds no end-to-end capability, and separation of duties is intact.

        This is the case that pins `resources_overlap`. Without it the overlap requirement could be
        deleted and every test still passed -- verified by removing it and seeing the suite stay
        green, which is why this case exists.
        """
        manager_a = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-a"
        )
        manager_b = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-b"
        )
        result = self._run(
            roles=[_Role(inline_policies=["session-on-a", "process-on-b"])],
            policies={
                f"{ROLE_ARN}:policy/session-on-a": _Policy(
                    _doc(["bedrock-agentcore:CreatePaymentSession"], resource=manager_a)
                ),
                f"{ROLE_ARN}:policy/process-on-b": _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], resource=manager_b)
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "halves on disjoint managers hold no end-to-end capability; got "
            f"{result[0].status}: {result[0].status_extended}"
        )
        # The role DOES hold both actions here, so the PASS sentence must not claim otherwise.
        # It previously read "allows ...CreatePaymentSession, ...ProcessPayment but not both payment
        # actions", contradicting the list it had just printed and reading as though the check had
        # missed the second grant rather than having found the managers disjoint.
        assert "not both payment actions" not in result[0].status_extended
        assert "do not overlap" in result[0].status_extended, (
            "the PASS reason must name the real one -- disjoint managers; got "
            f"{result[0].status_extended}"
        )

    @mock_aws
    def test_a_wildcard_grant_overlaps_a_specific_manager(self):
        """Ambiguity resolves towards FAIL: `"*"` and a concrete ARN can name the same manager.

        One policy granting an action on every resource and another granting the second action on one
        manager is still one role able to complete a payment on that manager, so the overlap test
        checks both directions rather than only pattern-against-target.
        """
        manager_a = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-a"
        )
        result = self._run(
            roles=[_Role(inline_policies=["session-everywhere", "process-on-a"])],
            policies={
                f"{ROLE_ARN}:policy/session-everywhere": _Policy(
                    _doc(["bedrock-agentcore:CreatePaymentSession"], resource="*")
                ),
                f"{ROLE_ARN}:policy/process-on-a": _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], resource=manager_a)
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_a_bracketed_resource_name_still_overlaps_itself(self):
        """The SAME resource on both halves is a violation whatever characters its name contains.

        Resource matching was `fnmatch`, which honours `[seq]` character classes. IAM does not: in a
        Resource pattern only `*` and `?` are metacharacters and every other character is literal. So
        a manager named `[prod]` was read as a one-character class matching `p`, `r`, `o` or `d`, the
        pattern did not match the identical string, `resources_overlap` returned False, and a role
        holding BOTH halves on ONE manager reported PASS.

        A pattern covers itself by definition; that must not depend on which characters it happens to
        contain.
        """
        bracketed = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/[prod]"
        )
        result = self._run(
            roles=[_Role(inline_policies=["session", "process"])],
            policies={
                f"{ROLE_ARN}:policy/session": _Policy(
                    _doc(["bedrock-agentcore:CreatePaymentSession"], resource=bracketed)
                ),
                f"{ROLE_ARN}:policy/process": _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], resource=bracketed)
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "both halves on one payment manager is a violation regardless of the characters in its "
            f"name; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_that_denies_nothing_cannot_suppress_the_finding(self):
        """A Deny inert under IAM must not subtract anything — the false-PASS case that matters most.

        `[!zzz]*` is not a negated character class to IAM; it is a literal resource name beginning
        `[!zzz]`, so the statement denies nothing that exists. Under `fnmatch` it read as "everything
        not starting with z", which covered every Allow on the role, emptied both effective resource
        sets and reported PASS for a role that can still open and execute a payment.

        That made the check evadable by whoever writes the policy: adding one inert Deny statement
        silenced the finding while changing no real permission. Explicit Deny wins where it bites, and
        a Deny that bites nothing may not win.
        """
        manager = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-a"
        )
        inert_deny = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/[!zzz]*"
        )
        result = self._run(
            roles=[_Role(inline_policies=["both", "inert-deny"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(
                    _doc(
                        [
                            "bedrock-agentcore:CreatePaymentSession",
                            "bedrock-agentcore:ProcessPayment",
                        ],
                        resource=manager,
                    )
                ),
                f"{ROLE_ARN}:policy/inert-deny": _Policy(
                    _doc(["bedrock-agentcore:*"], effect="Deny", resource=inert_deny)
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny whose Resource matches nothing under IAM must not suppress the violation; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_single_character_wildcard_in_a_deny_still_subtracts(self):
        """The control for the replacement matcher: `?` must keep matching exactly one character.

        `*` and `?` are the two metacharacters IAM does honour, and they came free from `fnmatch`. With
        a hand-written translation they have to be pinned, or "escape everything" would silently turn
        every wildcard Deny into a literal and every Deny into an inert one — a false FAIL everywhere,
        and the previous test would still pass.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both", "deny-single-char"])],
            policies={
                f"{ROLE_ARN}:policy/both": _Policy(BOTH_ACTIONS_DOC),
                f"{ROLE_ARN}:policy/deny-single-char": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        # PAYMENT_MANAGER_ARN ends "payment-manager/example"; "exampl?" matches it
                        # only if `?` consumes exactly the final "e".
                        resource=PAYMENT_MANAGER_ARN[:-1] + "?",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "`?` must match exactly one character, so this Deny does cover the allowed manager; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_two_patterns_that_intersect_without_either_containing_the_other(self):
        """The broadest surviving false PASS, and it needs no unusual characters at all.

        Both sides of every Resource comparison in this check are PATTERNS — a policy names
        `payment-manager/prod-*`, never the resources that match it today. Matching one compiled
        pattern against the other side's literal TEXT therefore treated a `*` in the subject as the
        character `*`, so two patterns could share a resource while neither one's text matched the
        other.

        `prod-*` and `*-checkout` both name `payment-manager/prod-checkout`. This role can open a
        session AND execute the payment on that manager, and the check reported PASS. Overlap is now
        pattern intersection, which is the question actually being asked.
        """
        manager_prefix = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}:payment-manager/"
        )
        result = self._run(
            roles=[_Role(inline_policies=["session-prod", "process-checkout"])],
            policies={
                f"{ROLE_ARN}:policy/session-prod": _Policy(
                    _doc(
                        ["bedrock-agentcore:CreatePaymentSession"],
                        resource=f"{manager_prefix}prod-*",
                    )
                ),
                f"{ROLE_ARN}:policy/process-checkout": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        resource=f"{manager_prefix}*-checkout",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            f"{manager_prefix}prod-checkout matches both patterns, so this role can complete a "
            f"payment on it; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_wildcards_in_different_arn_segments_still_overlap(self):
        """The same defect in the shape real policies take: wildcards in Region and Account.

        A grant written for every Region in one account and a grant written for one Region in every
        account both cover the concrete resource in this account and Region. Neither pattern's text
        matches the other, so this was a PASS.
        """
        result = self._run(
            roles=[_Role(inline_policies=["any-region", "any-account"])],
            policies={
                f"{ROLE_ARN}:policy/any-region": _Policy(
                    _doc(
                        ["bedrock-agentcore:CreatePaymentSession"],
                        resource=f"arn:aws:bedrock-agentcore:*:{AWS_ACCOUNT_NUMBER}:payment-manager/mgr-1",
                    )
                ),
                f"{ROLE_ARN}:policy/any-account": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        resource="arn:aws:bedrock-agentcore:us-east-1:*:payment-manager/mgr-1",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "both grants cover this account's us-east-1 mgr-1; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_single_character_deny_does_not_cancel_a_wildcard_allow(self):
        """A Deny must only subtract where it provably covers the whole Allow.

        `payment-manager/?` reaches single-character manager names only, so an Allow on
        `payment-manager/*` survives it for every longer name. Comparing the Deny's compiled pattern
        against the Allow's literal text made `?` match the Allow's `*` as one character, cancelling
        the entire grant and reporting PASS — the same shape as the `[!zzz]*` case, via `?` instead of
        a bracket class.

        Deny is now containment rather than a text match, and containment is deliberately SOUND rather
        than complete: where it cannot prove the Deny covers the Allow it leaves the Allow standing,
        which can only over-report. Claiming coverage falsely would delete a capability and hide a
        violation.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both-everywhere", "deny-one-char"])],
            policies={
                f"{ROLE_ARN}:policy/both-everywhere": _Policy(
                    _doc(
                        [
                            "bedrock-agentcore:CreatePaymentSession",
                            "bedrock-agentcore:ProcessPayment",
                        ],
                        resource=f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}:payment-manager/*",
                    )
                ),
                f"{ROLE_ARN}:policy/deny-one-char": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}:payment-manager/?",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny reaching only single-character names must not cancel an Allow covering every "
            f"name; got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_covering_the_whole_allow_still_subtracts(self):
        """The counterweight to the test above, so containment cannot be tightened into uselessness.

        A Deny on `payment-manager/*` genuinely contains an Allow on one concrete manager, so it must
        still remove the action. Without this, "never subtract unless the patterns are equal" would
        pass the previous test and silently stop honouring explicit Deny.
        """
        manager = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/manager-a"
        )
        result = self._run(
            roles=[_Role(inline_policies=["both-on-a", "deny-all-managers"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-a": _Policy(
                    _doc(
                        [
                            "bedrock-agentcore:CreatePaymentSession",
                            "bedrock-agentcore:ProcessPayment",
                        ],
                        resource=manager,
                    )
                ),
                f"{ROLE_ARN}:policy/deny-all-managers": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}:payment-manager/*",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a Deny on every payment manager does contain an Allow on one of them; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_resource_containing_a_newline_is_still_matched_by_a_wildcard(self):
        """`*` means any sequence, newlines included.

        The previous implementation compiled patterns to a regex without `re.DOTALL`, so `.*` stopped
        at a newline and `*` failed to cover a resource string containing one — a PASS for a role
        holding both halves. The relations now walk characters directly, so no character is special to
        them and this cannot recur.
        """
        odd_manager = (
            f"arn:aws:bedrock-agentcore:us-east-1:{AWS_ACCOUNT_NUMBER}"
            ":payment-manager/mgr\n1"
        )
        result = self._run(
            roles=[_Role(inline_policies=["session-everywhere", "process-odd"])],
            policies={
                f"{ROLE_ARN}:policy/session-everywhere": _Policy(
                    _doc(["bedrock-agentcore:CreatePaymentSession"], resource="*")
                ),
                f"{ROLE_ARN}:policy/process-odd": _Policy(
                    _doc(["bedrock-agentcore:ProcessPayment"], resource=odd_manager)
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "`*` covers every resource, newline or not; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_two_single_character_wildcards_in_different_positions_overlap(self):
        """The crossing-pattern family reached through `?` instead of `*`.

        `mgr-?1` and `mgr-1?` both name `mgr-11`. This is the only case pinning the single-character
        branch of the intersection test: every other overlap case here uses `*`, so that branch could
        be written as `and` instead of `or`, or deleted outright, and nothing else would notice.
        """
        result = self._run(
            roles=[_Role(inline_policies=["session-q1", "process-1q"])],
            policies={
                f"{ROLE_ARN}:policy/session-q1": _Policy(
                    _doc(
                        ["bedrock-agentcore:CreatePaymentSession"],
                        resource=f"{MANAGER_PREFIX}/mgr-?1",
                    )
                ),
                f"{ROLE_ARN}:policy/process-1q": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        resource=f"{MANAGER_PREFIX}/mgr-1?",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "mgr-?1 and mgr-1? both name mgr-11, so the role completes a payment end to end on it; "
            f"got {result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_prefix_scoped_deny_does_not_cancel_a_manager_wide_allow(self):
        """Pins that Deny uses CONTAINMENT while overlap uses INTERSECTION — they are not the same.

        A Deny on `prod-*` intersects an Allow on `*` without containing it, and the role can still
        open and execute a payment on every non-prod manager. Anyone later "simplifying" the two
        relations into one intersection predicate reports PASS here, reintroducing the narrow-Deny
        false PASS.

        This case is why the test exists separately from the others: the OLD pattern-against-text
        relation happens to get it right, so reverting the matcher alone leaves this green. Only
        collapsing the two relations changes the verdict here.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both-everywhere", "deny-prod"])],
            policies={
                f"{ROLE_ARN}:policy/both-everywhere": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource=f"{MANAGER_PREFIX}/*")
                ),
                f"{ROLE_ARN}:policy/deny-prod": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=f"{MANAGER_PREFIX}/prod-*",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny scoped to prod managers leaves every other manager reachable; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_manager_wide_deny_removes_a_prefix_scoped_allow(self):
        """The converse, so containment cannot be tightened into a blanket refusal.

        A Deny on every manager does contain an Allow on `prod-*`. Without this, a containment test
        that always returned False would satisfy the case above while silently turning every
        resource-scoped Deny into noise.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both-on-prod", "deny-all-managers"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-prod": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource=f"{MANAGER_PREFIX}/prod-*")
                ),
                f"{ROLE_ARN}:policy/deny-all-managers": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=f"{MANAGER_PREFIX}/*",
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a Deny on every manager does contain an Allow on prod-*; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_with_no_resource_element_subtracts_nothing(self):
        """The empty-Deny-pattern edge, exercised through the check rather than the predicate.

        A Deny statement with no `Resource` gets the empty pattern, which names nothing, so it can
        cancel no Allow. The dangerous way to write containment is to treat an exhausted Deny pattern
        as covering whatever remains of the Allow — that makes an EMPTY Deny contain an Allow on `*`
        and delete the whole grant. Containment needs every string the Allow names, and `*` names more
        than the empty one.

        An identity statement with neither `Resource` nor `NotResource` is malformed and IAM rejects
        it, which is exactly why nothing else pins this branch.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both-on-star", "deny-no-resource"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-star": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource="*")
                ),
                f"{ROLE_ARN}:policy/deny-no-resource": _Policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock-agentcore:ProcessPayment",
                            }
                        ],
                    }
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Deny naming no resource cannot cancel anything; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_deny_with_an_empty_resource_list_subtracts_nothing(self):
        """The same edge reached through ``"Resource": []``, which takes a different branch."""
        result = self._run(
            roles=[_Role(inline_policies=["both-on-star", "deny-empty-resource"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-star": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource="*")
                ),
                f"{ROLE_ARN}:policy/deny-empty-resource": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=[],
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "an empty Resource list names nothing; got "
            f"{result[0].status}: {result[0].status_extended}"
        )

    @mock_aws
    def test_a_resource_longer_than_the_recursion_limit_still_fails(self):
        """A Resource pattern too long to recurse over must not lose the FAIL.

        `resources_overlap` compares the ProcessPayment patterns against the CreatePaymentSession
        ones, here the same 1,000-plus-character pattern on both sides. Recursing once per character
        raised RecursionError, the executor swallowed it, and the check contributed no findings at
        all -- the quietest possible way to lose a payments separation-of-duties violation.
        """
        assert (
            len(LONG_MANAGER_ARN) > 993
        ), "shorter than the measured failure threshold"
        result = self._run(
            roles=[_Role(inline_policies=["both-on-a-long-manager"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-a-long-manager": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource=LONG_MANAGER_ARN)
                )
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL", (
            "a Resource too long to recurse over must still report the violation; got "
            f"{result[0].status}: {result[0].status_extended}"
        )
        assert "end-to-end" in result[0].status_extended

    @mock_aws
    def test_a_deny_on_a_resource_longer_than_the_recursion_limit_still_subtracts(self):
        """The same length reached through containment rather than intersection.

        `effective_resources_by_action` asks `_pattern_contains` whether the Deny covers the Allow,
        so a long pattern blew the stack on that path too. With one action denied the role holds a
        single payment half, and the verdict has to be PASS rather than a swallowed nothing.
        """
        result = self._run(
            roles=[_Role(inline_policies=["both-on-a-long-manager", "deny-process"])],
            policies={
                f"{ROLE_ARN}:policy/both-on-a-long-manager": _Policy(
                    _doc(BOTH_ACTION_NAMES, resource=LONG_MANAGER_ARN)
                ),
                f"{ROLE_ARN}:policy/deny-process": _Policy(
                    _doc(
                        ["bedrock-agentcore:ProcessPayment"],
                        effect="Deny",
                        resource=LONG_MANAGER_ARN,
                    )
                ),
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS", (
            "a Deny on the whole Allow removes one half; got "
            f"{result[0].status}: {result[0].status_extended}"
        )
        assert "CreatePaymentSession" in result[0].status_extended
        assert "ProcessPayment" not in result[0].status_extended

    @mock_aws
    def test_the_manual_text_does_not_depend_on_the_order_iam_returned_the_policies(
        self,
    ):
        """One role must not render as two different MANUAL findings across scans.

        `ListAttachedRolePolicies` documents no ordering, so the loop that collects the
        policies it could not read can visit them in either order. `granted_names` was
        already sorted; `unresolved` was not, so the same unreadable pair produced
        "managed policy a-first, managed policy z-second" on one scan and the reverse on
        the next. Same defect as the delegated-administrator listing.
        """
        arn_a = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/a-first"
        arn_z = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/z-second"
        forward = [
            {"PolicyArn": arn_a, "PolicyName": "a-first"},
            {"PolicyArn": arn_z, "PolicyName": "z-second"},
        ]
        # Neither ARN is present in `policies`, so both land in `unresolved` and the check
        # takes the MANUAL branch that renders the list.
        first = self._run(roles=[_Role(attached_policies=forward)], policies={})
        second = self._run(
            roles=[_Role(attached_policies=list(reversed(forward)))], policies={}
        )

        assert (
            len(first) == 1 and len(second) == 1
        ), f"both orderings must evaluate the one role; got {len(first)} and {len(second)}"
        assert first[0].status == "MANUAL" and second[0].status == "MANUAL", (
            "two unreadable policies leave the grant unknown, which is MANUAL; got "
            f"{first[0].status} and {second[0].status}"
        )
        assert first[0].status_extended == second[0].status_extended, (
            "the same role and the same unreadable policies produced two different finding "
            f"texts purely because IAM returned them in a different order:\n  "
            f"{first[0].status_extended}\n  {second[0].status_extended}"
        )
