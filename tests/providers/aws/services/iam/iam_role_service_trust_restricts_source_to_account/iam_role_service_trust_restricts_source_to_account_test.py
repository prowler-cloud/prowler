from unittest import mock

import pytest

from prowler.providers.aws.services.iam.iam_service import Role
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

AWS_ACCOUNT_ID = "123456789012"
OTHER_ACCOUNT_ID = "999988887777"
SERVICE = "sagemaker.amazonaws.com"
SCOPED_ARN = f"arn:aws:sagemaker:us-east-1:{AWS_ACCOUNT_ID}:training-job/my-job"
# An S3 bucket ARN has an EMPTY account field, which is why AWS documents needing
# aws:SourceAccount alongside it.
BUCKET_ARN = "arn:aws:s3:::amzn-s3-demo-bucket"

CHECK_MODULE = "prowler.providers.aws.services.iam.iam_role_service_trust_restricts_source_to_account.iam_role_service_trust_restricts_source_to_account"


def _trust_policy(statements: list) -> dict:
    """Wrap statements in a trust policy document."""
    return {"Version": "2012-10-17", "Statement": statements}


def _service_statement(condition: dict = None, principal: dict = None) -> dict:
    """Build an Allow of sts:AssumeRole to a service principal, condition optional.

    Omitting the condition produces the wholly-unconditional shape, which this check treats as
    out of scope; `principal` overrides the default so a test can build a hybrid principal.
    """
    statement = {
        "Effect": "Allow",
        "Principal": principal if principal is not None else {"Service": SERVICE},
        "Action": "sts:AssumeRole",
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _role(name: str, statements: list, arn: str = None, is_service_role: bool = True):
    """Build a Role carrying the given trust statements.

    `arn` is overridable because the service-linked exclusion is keyed on the ARN path, not on
    `is_service_role`.
    """
    return Role(
        name=name,
        arn=arn or f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{name}",
        assume_role_policy=_trust_policy(statements),
        is_service_role=is_service_role,
        tags=[],
    )


def _run(roles: list):
    """Execute the check against the given roles and return its reports.

    The roles are model objects, so the reports exercise the check's own trust-policy parsing
    without any IAM API call.
    """
    iam_client = mock.MagicMock()
    iam_client.roles = roles
    iam_client.region = AWS_REGION_US_EAST_1
    iam_client.audited_account = AWS_ACCOUNT_ID

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    aws_provider.identity.account = AWS_ACCOUNT_ID

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.aws.services.iam.iam_role_service_trust_restricts_source_to_account.iam_role_service_trust_restricts_source_to_account import (
            iam_role_service_trust_restricts_source_to_account,
        )

        return iam_role_service_trust_restricts_source_to_account().execute()


ACCOUNT_ONLY = {"StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID}}
ARN_ONLY = {"ArnLike": {"aws:SourceArn": SCOPED_ARN}}
BOTH_SCOPED = {
    "StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID},
    "ArnLike": {"aws:SourceArn": SCOPED_ARN},
}


class Test_iam_role_service_trust_restricts_source_to_account:
    def test_no_roles(self):
        """An account with no roles produces no reports at all."""
        assert len(_run([])) == 0

    def test_service_linked_role_skipped(self):
        """A service-linked role is excluded even when its trust policy would FAIL.

        Its trust relationship is managed by the service and cannot be edited, so a finding would
        not be actionable. The fixture is a failing one, so the zero measures the exclusion rather
        than the scope gate.
        """
        role = _role(
            "AWSServiceRoleForAmazonSageMaker",
            [
                _service_statement(
                    {"ArnLike": {"aws:SourceArn": "arn:aws:sagemaker:*:*:*"}}
                )
            ],
            arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/aws-service-role/{SERVICE}/AWSServiceRoleForAmazonSageMaker",
        )
        assert len(_run([role])) == 0

    def test_role_without_service_principal_skipped(self):
        """A role trusting only an AWS principal is out of scope: no service is involved."""
        role = _role(
            "human-role",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
            is_service_role=False,
        )
        assert len(_run([role])) == 0

    def test_non_assume_role_action_skipped(self):
        """A statement granting only sts:TagSession cannot be used to assume the role, so no finding."""
        role = _role(
            "tag-only-role",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:TagSession",
                }
            ],
        )
        assert len(_run([role])) == 0

    def test_wildcard_action_that_cannot_reach_assume_role_skipped(self):
        """A wildcard action whose prefix does not lead to sts:AssumeRole is out of scope.

        `sts:Tag*` ends in a wildcard but expands to no assume-role action, so the statement
        grants nobody the ability to assume this role and belongs outside the population. The
        condition is present and enforced but pins no source, so were the statement wrongly
        admitted the role would FAIL -- which is what makes 0 findings here a real assertion
        rather than an absence that any exclusion would produce. `sts:TagSession` alone cannot
        make this claim: it carries no wildcard, so it is excluded by the literal test that
        precedes the wildcard test and leaves the wildcard branch unexercised.
        """
        role = _role(
            "tag-wildcard-role",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:Tag*",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}
                    },
                }
            ],
        )
        assert len(_run([role])) == 0

    @pytest.mark.parametrize(
        "action",
        ["sts:*Role", "sts:A*Role", "sts:Assume?ole", "sts:AssumeRol?", "sts:As*me*le"],
    )
    def test_a_wildcard_not_at_the_end_still_grants_assume_role(self, action):
        """Every IAM spelling that reaches sts:AssumeRole must bring the statement into scope.

        A literal tuple plus a trailing-star test recognised only a star at the END, so each of
        these granted the action while the statement fell out of the evaluated population and the
        role produced NO REPORT. The condition here is present and enforced but pins no source, so
        an admitted statement FAILs -- which is what makes this a verdict assertion rather than an
        absence any exclusion would produce.
        """
        role = _role(
            "midstar-role",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": action,
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}
                    },
                }
            ],
        )
        result = _run([role])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_a_midstar_statement_beside_a_scoped_one_is_not_a_pass(self):
        """The two-statement form of the miss above, which was an affirmative false PASS.

        The unscoped statement went unseen, leaving only the properly scoped one in the
        population, so the check asserted the role confines every service principal to an account
        while a second statement trusted one with no source binding at all. Silence would have
        been better than this; the full sentence is asserted so the claim cannot be made quietly.
        """
        role = _role(
            "midstar-and-scoped-role",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:*Role",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}
                    },
                },
                _service_statement(
                    {"StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID}}
                ),
            ],
        )
        result = _run([role])
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "IAM Role midstar-and-scoped-role trusts an AWS service principal without confining "
            "the request source, since no condition pins aws:SourceAccount to a literal account "
            "ID, aws:SourceArn to an ARN carrying one, or aws:SourceOrgID or "
            "aws:SourceOrgPaths to an organization."
        )

    @pytest.mark.parametrize(
        "statement",
        [
            {"Effect": "Allow", "Principal": {"Service": SERVICE}, "Action": None},
            {
                "Effect": "Allow",
                "Principal": {"Service": None},
                "Action": "sts:AssumeRole",
            },
        ],
        ids=["null-action", "null-service"],
    )
    def test_a_present_but_null_key_does_not_abort_the_check(self, statement):
        """A key present with a null value must not raise out of execute().

        `.get("Action", [])` returns None for `"Action": null` rather than the default, and
        iterating None raises TypeError, which check.py's bare except cannot usefully contain: it
        discards every finding for the ACCOUNT, not one role. Both sibling checks normalise
        through _as_list and were immune; this one had two such reads. IAM rejects these documents
        so the state is unreachable through GetRole -- the assertion is that the check behaves like
        its siblings, not that a real policy can reach it.
        """
        assert len(_run([_role("null-key-role", [statement])])) == 0

    def test_deny_statement_skipped(self):
        """A Deny statement grants nothing, so a trust policy of only Denies yields no finding."""
        role = _role(
            "deny-role",
            [
                {
                    "Effect": "Deny",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:AssumeRole",
                }
            ],
        )
        assert len(_run([role])) == 0

    def test_empty_trust_policy_skipped(self):
        """A role whose trust policy is empty has no statement to evaluate."""
        role = Role(
            name="empty-role",
            arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/empty-role",
            assume_role_policy={},
            is_service_role=True,
            tags=[],
        )
        assert len(_run([role])) == 0

    # ---------------- SCOPE: the wholly-unconditional posture is not ours ----------------

    def test_plain_service_role_without_any_condition_is_out_of_scope(self):
        """The fully-unprotected posture belongs to the sibling check, not to this one.

        Reporting it here would make this check a strict superset of
        iam_role_cross_service_confused_deputy_prevention: measured against 366 real roles,
        195 of its 199 findings are exactly this shape. Staying silent is what keeps the
        two checks complementary.
        """
        assert len(_run([_role("unscoped-role", [_service_statement()])])) == 0

    def test_deny_statement_brings_the_allow_statement_into_scope(self):
        """A Deny statement puts the policy outside every existing service-role check.

        Modelled on a real role: upstream's is_service_role requires Effect == "Allow" on
        EVERY statement, so adding a Deny hardening statement silently removes the role
        from the sibling's evaluated population. No other check assesses it.
        """
        role = _role(
            "allow-plus-deny-role",
            [
                _service_statement(),
                {
                    "Effect": "Deny",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Null": {"aws:RequestTag/Attr": "false"}},
                },
            ],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_non_assume_action_statement_brings_the_policy_into_scope(self):
        """Modelled on a real role whose second statement grants sts:SetContext.

        is_service_role matches its action list by substring against sts:AssumeRole, sts:*
        and *, none of which appear in "sts:SetContext", so the whole role drops out of the
        sibling's population.
        """
        role = _role(
            "assume-plus-setcontext-role",
            [
                _service_statement(),
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": "sts:SetContext",
                },
            ],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    # ---------------- FAIL: the source is not confined to an account ----------------

    def test_source_arn_without_account_field_alone_fails(self):
        """A bucket ARN pins the resource but not the account -- AWS requires both here."""
        role = _role(
            "bucket-arn-role",
            [_service_statement({"ArnLike": {"aws:SourceArn": BUCKET_ARN}})],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_source_arn_global_wildcard_fails(self):
        """aws:SourceArn of "*" pins nothing, so the source is unconfined and it FAILs."""
        role = _role(
            "wildcard-arn-role",
            [_service_statement({"ArnLike": {"aws:SourceArn": "*"}})],
        )
        assert _run([role])[0].status == "FAIL"

    def test_source_arn_wildcard_account_fails(self):
        """An ARN whose account field is a wildcard confines the caller to no account, so FAIL."""
        role = _role(
            "wildcard-account-arn-role",
            [
                _service_statement(
                    {"ArnLike": {"aws:SourceArn": "arn:aws:sagemaker:*:*:*"}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_source_arn_list_with_one_accountless_value_fails(self):
        """One accountless value in a SourceArn list is enough to FAIL.

        Every value must bear an account: IAM satisfies the condition with any one of them, so a
        scoped sibling does not narrow the accountless entry.
        """
        role = _role(
            "mixed-arn-list-role",
            [
                _service_statement(
                    {"ArnLike": {"aws:SourceArn": [SCOPED_ARN, BUCKET_ARN]}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_source_account_wildcard_value_fails(self):
        """aws:SourceAccount of "*" names no account, so it FAILs."""
        role = _role(
            "wildcard-account-role",
            [_service_statement({"StringLike": {"aws:SourceAccount": "*"}})],
        )
        assert _run([role])[0].status == "FAIL"

    def test_source_account_partial_value_fails(self):
        """A partial account value such as 1234* is not a literal 12-digit account, so it FAILs."""
        role = _role(
            "partial-account-role",
            [_service_statement({"StringLike": {"aws:SourceAccount": "1234*"}})],
        )
        assert _run([role])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "condition",
        [
            {
                "StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                "StringLike": {"aws:SourceAccount": "*"},
            },
            {
                "StringEquals": {"aws:SourceOrgID": "o-abcdefghij"},
                "StringEqualsIgnoreCase": {"aws:SourceOrgID": "O-ABCDEFGHIJ"},
            },
            {
                "ArnEquals": {"aws:SourceArn": SCOPED_ARN},
                "ArnLike": {"aws:SourceArn": "arn:aws:sagemaker:*:*:*"},
            },
        ],
        ids=[
            "account-plus-broad-stringlike",
            "org-id-pair",
            "arn-equals-plus-arn-like",
        ],
    )
    def test_a_second_operator_cannot_make_a_pinned_statement_fail(self, condition):
        """Adding an ANDed operator must never turn a confined statement into a finding.

        Every value was pooled into one list and then required to qualify, so a statement pinning
        the account with StringEquals FAILed as soon as a broader StringLike sat beside it -- while
        the same statement with that operator DELETED PASSed. An ANDed operator can only narrow the
        set of requests that satisfy the statement, so no addition can make it less confined.

        The org-id pair carries no wildcard at all, which shows the cause was the pooling and not
        the wildcard. It needs the second value differently cased to reproduce, and that is not
        contrivance: ORGANIZATION_ID_PATTERN is case-sensitive, so an upper-case org ID is exactly
        what StringEqualsIgnoreCase is FOR, and pooling it beside the exact pin dragged the whole
        statement down. An identically-cased pair does not reproduce it -- I wrote that fixture
        first and the control showed it passing before the fix, measuring nothing.
        """
        role = _role("pooled-operators-role", [_service_statement(condition)])
        assert _run([role])[0].status == "PASS"

    def test_two_values_under_one_operator_must_both_qualify(self):
        """Within a single operator, one unqualified value still FAILs.

        The guard on the fix above. IAM lets a request match ANY value listed under one operator,
        so a real account ID beside "*" confines nothing -- and it would be easy to fix the pooling
        by relaxing this from all() to any(), which would clear exactly this policy.
        """
        role = _role(
            "mixed-values-role",
            [
                _service_statement(
                    {"StringLike": {"aws:SourceAccount": [AWS_ACCOUNT_ID, "*"]}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_if_exists_operator_is_not_a_binding(self):
        """*IfExists is skipped when the calling service omits the key, so it binds nothing.

        On a plain service role this is out of scope -- an unenforced operator leaves the
        statement wholly unconstrained, which is the sibling's finding. The assertion that
        *IfExists is not a binding is made on a role that IS in scope, below.
        """
        role = _role(
            "ifexists-role",
            [
                _service_statement(
                    {"StringEqualsIfExists": {"aws:SourceAccount": AWS_ACCOUNT_ID}}
                )
            ],
        )
        assert len(_run([role])) == 0

    def test_if_exists_operator_fails_when_in_scope(self):
        """*IfExists binds nothing, and on an in-scope role that is a FAIL rather than silence.

        The hybrid principal is what puts the role in scope, so this makes the assertion the plain
        service role above cannot: that an unenforced operator is not a binding.
        """
        role = _role(
            "ifexists-hybrid-role",
            [
                _service_statement(
                    {"StringEqualsIfExists": {"aws:SourceAccount": AWS_ACCOUNT_ID}},
                    principal={
                        "Service": SERVICE,
                        "AWS": f"arn:aws:iam::{OTHER_ACCOUNT_ID}:root",
                    },
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_negated_operator_is_not_a_binding(self):
        """StringNotEquals inverts the match, so on a plain service role the statement is unconstrained.

        That wholly-unconstrained posture belongs to the sibling check, so this yields no finding.
        """
        role = _role(
            "negated-role",
            [
                _service_statement(
                    {"StringNotEquals": {"aws:SourceAccount": OTHER_ACCOUNT_ID}}
                )
            ],
        )
        assert len(_run([role])) == 0

    def test_negated_operator_fails_when_in_scope(self):
        """A negated operator on an in-scope role FAILs rather than passing as a binding."""
        role = _role(
            "negated-hybrid-role",
            [
                _service_statement(
                    {"StringNotEquals": {"aws:SourceAccount": OTHER_ACCOUNT_ID}},
                    principal={
                        "Service": SERVICE,
                        "AWS": f"arn:aws:iam::{OTHER_ACCOUNT_ID}:root",
                    },
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_unrelated_condition_key_fails(self):
        """A condition on an unrelated key is present but confines no source, so it FAILs.

        aws:PrincipalOrgID constrains who calls, not which resource's service call it came from,
        which is the confused-deputy question.
        """
        role = _role(
            "org-principal-role",
            [
                _service_statement(
                    {"StringEquals": {"aws:PrincipalOrgID": "o-abc123defg"}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_hybrid_principal_unconditional_fails(self):
        """The blind spot: a Service principal paired with a cross-account AWS principal."""
        role = _role(
            "hybrid-role",
            [
                _service_statement(
                    principal={
                        "Service": SERVICE,
                        "AWS": f"arn:aws:iam::{OTHER_ACCOUNT_ID}:root",
                    }
                )
            ],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_wildcard_action_unconditional_is_out_of_scope(self):
        """An unconditional Action:* grant is the sibling's most severe finding, not ours."""
        role = _role(
            "wildcard-action-role",
            [{"Effect": "Allow", "Principal": {"Service": SERVICE}, "Action": "*"}],
        )
        assert len(_run([role])) == 0

    def test_scoped_statement_beside_an_unconditional_one_is_out_of_scope(self):
        """Modelled on two real AgentCore gateway roles in the measured account.

        A redundant unconditional statement sitting beside a properly scoped one is a real
        finding, but it is the sibling's: the unconditional statement has no constraint at
        all. Both of those roles appear in the sibling's FAIL set.
        """
        role = _role(
            "partially-scoped-role",
            [_service_statement(BOTH_SCOPED), _service_statement()],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_one_conditioned_but_unbound_statement_of_many_fails(self):
        """A present-but-insufficient constraint on any one statement is ours to report."""
        role = _role(
            "partially-scoped-role",
            [
                _service_statement(BOTH_SCOPED),
                _service_statement({"ArnLike": {"aws:SourceArn": BUCKET_ARN}}),
            ],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    # ---------------- PASS: the source is confined to an account ----------------

    def test_source_account_alone_passes(self):
        """aws:SourceAccount alone confines the caller to one account."""
        findings = _run(
            [_role("account-only-role", [_service_statement(ACCOUNT_ONLY)])]
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "confines every AWS service principal" in findings[0].status_extended

    def test_account_bearing_source_arn_alone_passes(self):
        """AWS calls a full aws:SourceArn the most effective protection -- no SourceAccount needed."""
        findings = _run([_role("arn-only-role", [_service_statement(ARN_ONLY)])])
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_account_bearing_source_arn_with_arn_equals_passes(self):
        """ArnEquals is an enforcing operator, so an account-bearing SourceArn under it PASSes."""
        role = _role(
            "arn-equals-role",
            [_service_statement({"ArnEquals": {"aws:SourceArn": SCOPED_ARN}})],
        )
        assert _run([role])[0].status == "PASS"

    def test_account_bearing_source_arn_with_resource_wildcard_passes(self):
        """arn:...:<account>:* still confines the caller to that account."""
        role = _role(
            "arn-resource-wildcard-role",
            [
                _service_statement(
                    {
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:sagemaker:us-east-1:{AWS_ACCOUNT_ID}:*"
                        }
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_bucket_arn_with_source_account_passes(self):
        """An accountless bucket ARN paired with aws:SourceAccount PASSes.

        This is AWS's documented remedy for ARNs that carry no account field: the two keys together
        confine the source even though neither does alone.
        """
        role = _role(
            "bucket-arn-scoped-role",
            [
                _service_statement(
                    {
                        "ArnLike": {"aws:SourceArn": BUCKET_ARN},
                        "StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_source_account_with_a_same_key_null_guard_passes(self):
        """AWS's prescribed pairing -- a comparison plus Null:"false" on the same key -- must PASS.

        `Null` is a presence test, not a comparison, so it pins no value. Reading it as one put the
        literal string "false" beside a real account ID, and _pins_source_account requires EVERY
        value to be a 12-digit account, so the shape test failed and the role FAILed. That made the
        more secure policy score worse than the same policy without the guard, which is the worst
        possible direction for a check to be wrong in.
        """
        role = _role(
            "account-with-null-guard",
            [
                _service_statement(
                    {
                        "StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                        "Null": {"aws:SourceAccount": "false"},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_null_guard_alone_pins_nothing_and_fails(self):
        """A Null guard with no comparison beside it confines the source to nothing, so FAIL.

        The guard forces the key to be present; it says nothing about which account. Crediting it
        would clear a statement bound to no account at all, and the guard's own marker value is not
        an account ID.
        """
        role = _role(
            "null-only",
            [_service_statement({"Null": {"aws:SourceAccount": "false"}})],
        )
        assert _run([role])[0].status == "FAIL"

    def test_for_all_values_without_a_null_guard_fails(self):
        """Unguarded ForAllValues is vacuous on an Allow, so it must not be credited.

        AWS documents that it "returns true if there are no context keys in the request", with an
        explicit warning against pairing it with an Allow effect -- and this check evaluates Allow
        statements only, so that is the reachable case. A caller who simply omits aws:SourceAccount
        satisfies it, which is the same vacuity *IfExists has; both are credited only under the
        Null:"false" guard, and neither without it.
        """
        role = _role(
            "for-all-values-unguarded",
            [
                _service_statement(
                    {"ForAllValues:StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_for_all_values_with_a_same_key_null_guard_passes(self):
        """ForAllValues paired with Null:"false" on the SAME key is not vacuous, so it PASSes.

        The guard forces the key to be present, which removes the no-context-keys escape. Refusing
        the guarded spelling outright would be wrong rather than merely strict: aws:SourceOrgPaths is
        multivalued, so a set operator is the only correct way to write a binding for it. The guard
        must be on the same key -- one on a different key leaves this one vacuous.
        """
        role = _role(
            "for-all-values-guarded",
            [
                _service_statement(
                    {
                        "ForAllValues:StringEquals": {
                            "aws:SourceAccount": AWS_ACCOUNT_ID
                        },
                        "Null": {"aws:SourceAccount": "false"},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_for_all_values_with_a_null_guard_on_a_different_key_fails(self):
        """A Null guard rescues only the key it names, so a guard elsewhere leaves this one vacuous.

        The guard on aws:SourceArn forces THAT key to be present; it says nothing about
        aws:SourceAccount, so the ForAllValues binding on the account is still satisfied by a caller
        who simply omits it. The same-key test above cannot make this assertion: it uses one key for
        both, so a rule requiring a guard on ANY key would pass it just as happily.
        """
        role = _role(
            "for-all-values-guard-on-another-key",
            [
                _service_statement(
                    {
                        "ForAllValues:StringEquals": {
                            "aws:SourceAccount": AWS_ACCOUNT_ID
                        },
                        "Null": {"aws:SourceArn": "false"},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "guard",
        [["true", "false"], ["false", "true"]],
        ids=["ors-to-always-true", "ors-to-always-true-reversed"],
    )
    def test_a_null_guard_list_containing_true_rescues_nothing(self, guard):
        """A Null list containing "true" binds NOTHING, because IAM ORs the values in one operator.

        `Null: {aws:SourceAccount: ["true","false"]}` reads as "key absent OR key present", which is
        always satisfied, so it cannot force the key to be present and cannot rescue the ForAllValues
        binding beside it. Reading the list with `any` credited it anyway, which meant ADDING the word
        "true" to a guard list moved the verdict from FAIL to PASS -- a strictly weaker policy scoring
        better, which is the same inversion this check was already fixed for once.

        Measured on IAM's own evaluator with the key omitted: `allowed` for both orderings,
        indistinguishable from carrying no Null block at all, against `implicitDeny` for "false",
        ["false"] and ["false","false"]. Reachable on THIS surface specifically: create_role stores
        ["true","false"] and get_role returns it as a list, even though a single-element ["false"] is
        collapsed to the scalar "false" here -- which is why the multi-value spelling is the one that
        matters and the single-value one cannot be tested end-to-end.

        Both orderings are pinned because a fix reading only the first element would satisfy one of
        them and not the other.
        """
        role = _role(
            "null-guard-list-with-true",
            [
                _service_statement(
                    {
                        "ForAllValues:StringEquals": {
                            "aws:SourceAccount": AWS_ACCOUNT_ID
                        },
                        "Null": {"aws:SourceAccount": guard},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_null_guard_demanding_the_key_be_absent_does_not_rescue_for_all_values(
        self,
    ):
        """`Null: "true"` demands the key be ABSENT, which makes ForAllValues vacuous by design.

        Only `"false"` forces presence. Accepting any value as a guard would read this policy -- which
        requires aws:SourceAccount NOT to be supplied -- as though it required the opposite, and the
        two guarded tests above use `"false"` so neither distinguishes the values.
        """
        role = _role(
            "for-all-values-null-true",
            [
                _service_statement(
                    {
                        "ForAllValues:StringEquals": {
                            "aws:SourceAccount": AWS_ACCOUNT_ID
                        },
                        "Null": {"aws:SourceAccount": "true"},
                    }
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "condition",
        [
            {
                "StringEqualsIfExists": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                "Null": {"aws:SourceAccount": "false"},
            },
            {
                "ArnLikeIfExists": {"aws:SourceArn": SCOPED_ARN},
                "Null": {"aws:SourceArn": "false"},
            },
            {
                "ForAllValues:StringLikeIfExists": {
                    "aws:SourceAccount": AWS_ACCOUNT_ID
                },
                "Null": {"aws:SourceAccount": "false"},
            },
        ],
        ids=["string-equals", "arn-like", "for-all-values-string-like"],
    )
    def test_a_guarded_if_exists_operator_is_a_binding(self, condition):
        """A guarded *IfExists must PASS, exactly as a guarded ForAllValues does.

        *IfExists and ForAllValues are two spellings of one trap -- a caller who omits the key
        satisfies both -- and `Null: "false"` forces the key to be present, which defeats the
        vacuity identically in either. Rescuing only ForAllValues meant these three FAILed while
        `ForAllValues:StringEquals` with the identical guard PASSed. That asymmetry punished
        policies for the operator they chose rather than for what they constrain, and
        secretsmanager_has_restrictive_resource_policy already accepts IfExists paired with Null.
        """
        role = _role("guarded-ifexists", [_service_statement(condition)])
        assert _run([role])[0].status == "PASS"

    @pytest.mark.parametrize(
        "condition",
        [
            {
                "StringEqualsIfExists": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                "Null": {"aws:SourceArn": "false"},
            },
            {
                "StringEqualsIfExists": {"aws:SourceAccount": AWS_ACCOUNT_ID},
                "Null": {"aws:SourceAccount": "true"},
            },
        ],
        ids=["guard-on-a-different-key", "guard-demanding-absence"],
    )
    def test_an_if_exists_operator_needs_the_same_guard_for_all_values_needs(
        self, condition
    ):
        """The rescue must require the SAME guard, not merely the presence of a Null block.

        A guard on a different key leaves aws:SourceAccount omissible, and `Null: "true"` demands
        the key be absent, which makes the operator vacuous by design rather than rescuing it. Both
        mirror the ForAllValues cases above, so the two families are now pinned to one rule in both
        directions -- without these, "credit a guarded IfExists" could be satisfied by any Null
        block anywhere in the statement.
        """
        role = _role("ifexists-bad-guard", [_service_statement(condition)])
        assert _run([role])[0].status == "FAIL"

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringLike": {"aws:SourceAccount": "1234*"}},
            {"ForAllValues:StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID}},
            {"Null": {"aws:SourceAccount": "false"}},
        ],
        ids=["partial-value", "unguarded-for-all-values", "null-guard-only"],
    )
    def test_the_fail_message_does_not_claim_the_key_is_unset(self, condition):
        """The FAIL sentence must describe what was measured, on inputs that SET the key.

        All three of these set aws:SourceAccount, so the previous wording -- "it sets neither
        aws:SourceAccount nor an account-bearing aws:SourceArn" -- was false of every one of them.
        What the code measures is that no condition PINS the key to a literal value of the right
        shape, which is weaker and true. The string is asserted in full because a status_extended
        change is invisible to a suite that only checks the status, and it ships in every CSV and
        OCSF row.
        """
        role = _role("fail-wording", [_service_statement(condition)])
        result = _run([role])
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "IAM Role fail-wording trusts an AWS service principal without confining the request "
            "source, since no condition pins aws:SourceAccount to a literal account ID, "
            "aws:SourceArn to an ARN carrying one, or aws:SourceOrgID or aws:SourceOrgPaths to an "
            "organization."
        )

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_ID}},
            {"ArnLike": {"aws:SourceArn": SCOPED_ARN}},
        ],
        ids=["source-account", "account-bearing-source-arn"],
    )
    def test_the_account_pass_message_is_used_for_account_scoping(self, condition):
        """An account-confined PASS keeps the account sentence."""
        role = _role("account-pass", [_service_statement(condition)])
        result = _run([role])
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "IAM Role account-pass confines every AWS service principal in its trust policy to a "
            "specific account."
        )

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEquals": {"aws:SourceOrgID": "o-abcdefghij"}},
            {
                "StringLike": {
                    "aws:SourceOrgPaths": "o-abcdefghij/r-abc1/ou-abc1-12345678/"
                }
            },
        ],
        ids=["source-org-id", "source-org-paths"],
    )
    def test_an_org_scoped_pass_does_not_claim_a_specific_account(self, condition):
        """An organization-confined PASS must NOT claim confinement to a specific account.

        Both of these reach PASS through _pins_source_organization, and an organization may hold
        hundreds of accounts. The account sentence fired verbatim on them, telling an operator
        something categorically stronger than the check verified -- and over-claiming on a PASS is
        the worse direction, because a PASS is filed as clean and nobody looks again.
        """
        role = _role("org-pass", [_service_statement(condition)])
        result = _run([role])
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "IAM Role org-pass confines every AWS service principal in its trust policy, but at "
            "least one statement is scoped to an organization rather than to a single account, so "
            "the trusted source may be any account within it."
        )
        assert "to a specific account" not in result[0].status_extended

    @pytest.mark.parametrize(
        "value",
        ["*", "o-abcdefghij", "not-an-ou-path"],
        ids=["star", "org-id-not-a-path", "junk"],
    )
    def test_a_source_org_paths_value_that_is_not_an_ou_path_fails(self, value):
        """aws:SourceOrgPaths must hold an OU PATH, so these three must FAIL.

        Replacing the org-paths arm's shape test with `bool(org_paths)` left the whole suite green
        while a statement carrying `aws:SourceOrgPaths: "*"` reported PASS -- the same false PASS the
        o-* negative already prevents for aws:SourceOrgID, unpinned on this arm. The middle value is
        the discriminating one: a bare org ID is a valid ORG id and not a valid org PATH, so it
        separates the path pattern from the id pattern rather than merely rejecting junk.
        """
        role = _role(
            "org-paths-shape",
            [
                _service_statement(
                    {"ForAnyValue:StringLike": {"aws:SourceOrgPaths": value}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_both_keys_pass(self):
        """Both source keys present and well formed PASSes."""
        findings = _run([_role("both-role", [_service_statement(BOTH_SCOPED)])])
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_string_like_source_account_passes(self):
        """StringLike carrying a literal 12-digit account still pins it, so PASS.

        The operator permits wildcards but this value uses none, so the account is confined.
        """
        role = _role(
            "string-like-role",
            [_service_statement({"StringLike": {"aws:SourceAccount": AWS_ACCOUNT_ID}})],
        )
        assert _run([role])[0].status == "PASS"

    def test_lowercase_condition_keys_pass(self):
        """Condition key names are case-insensitive in IAM."""
        role = _role(
            "lowercase-role",
            [
                _service_statement(
                    {"StringEquals": {"aws:sourceaccount": AWS_ACCOUNT_ID}}
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_source_account_list_passes(self):
        """A list of literal account IDs confines the source to those accounts, so PASS."""
        role = _role(
            "account-list-role",
            [
                _service_statement(
                    {
                        "StringEquals": {
                            "aws:SourceAccount": [AWS_ACCOUNT_ID, OTHER_ACCOUNT_ID]
                        }
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_source_org_id_passes(self):
        """AWS documents aws:SourceOrgID as an alternative source key."""
        role = _role(
            "org-id-role",
            [_service_statement({"StringEquals": {"aws:SourceOrgID": "o-a1b2c3d4e5"}})],
        )
        assert _run([role])[0].status == "PASS"

    def test_source_org_paths_passes(self):
        """aws:SourceOrgPaths under ForAnyValue:StringLike confines the source to an OU path, so PASS."""
        role = _role(
            "org-paths-role",
            [
                _service_statement(
                    {
                        "ForAnyValue:StringLike": {
                            "aws:SourceOrgPaths": "o-a1b2c3d4e5/r-f6g7h8i9j0/ou-f6g7-11112222/*"
                        }
                    }
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_source_org_id_wildcard_fails(self):
        """aws:SourceOrgID of "o-*" matches every organization, so it confines nothing and FAILs.

        The organization keys are accepted only when the value is a real identifier; accepting the
        key's presence alone would clear a statement bound to nothing.
        """
        role = _role(
            "org-id-wildcard-role",
            [_service_statement({"StringLike": {"aws:SourceOrgID": "o-*"}})],
        )
        assert _run([role])[0].status == "FAIL"

    def test_external_id_does_not_bind_the_source(self):
        """A concrete sts:ExternalId is not a cross-service mitigation.

        AWS documents the external ID for third-party access only -- it is a value the
        third party supplies -- and the cross-service guidance names aws:SourceArn and
        aws:SourceAccount. An AWS service passes neither an external ID nor anything that
        satisfies this condition, so crediting it would accept a control the calling
        service can never meet. The statement is in scope because a condition is present.
        """
        role = _role(
            "external-id-role",
            [
                _service_statement(
                    {"StringEquals": {"sts:ExternalId": "unique-tenant-id"}}
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_hybrid_principal_scoped_passes(self):
        """A hybrid principal is in scope, and PASSes when the source IS confined.

        So the hybrid shape is not treated as a finding in itself -- only as one no other check
        evaluates.
        """
        role = _role(
            "hybrid-scoped-role",
            [
                _service_statement(
                    ACCOUNT_ONLY,
                    principal={
                        "Service": SERVICE,
                        "AWS": f"arn:aws:iam::{OTHER_ACCOUNT_ID}:root",
                    },
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_service_principal_list_all_scoped_passes(self):
        """Several service principals in one statement PASS when the shared condition confines them."""
        role = _role(
            "service-list-role",
            [
                _service_statement(
                    ACCOUNT_ONLY,
                    principal={"Service": [SERVICE, "events.amazonaws.com"]},
                )
            ],
        )
        assert _run([role])[0].status == "PASS"

    def test_service_principal_list_unscoped_fails(self):
        """Several service principals under an unconfining condition FAIL together.

        The condition applies to the whole statement, so every principal in the list inherits it.
        """
        role = _role(
            "service-list-unscoped-role",
            [
                _service_statement(
                    {"ArnLike": {"aws:SourceArn": BUCKET_ARN}},
                    principal={"Service": [SERVICE, "events.amazonaws.com"]},
                )
            ],
        )
        assert _run([role])[0].status == "FAIL"

    def test_single_statement_dict_is_handled(self):
        """A Statement given as a single dict rather than a list is still evaluated.

        IAM accepts both shapes, so a check reading only lists would silently skip the role.
        """
        role = Role(
            name="single-statement-role",
            arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/single-statement-role",
            assume_role_policy={
                "Version": "2012-10-17",
                "Statement": _service_statement(
                    {"ArnLike": {"aws:SourceArn": BUCKET_ARN}}
                ),
            },
            is_service_role=True,
            tags=[],
        )
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_mixed_action_list_containing_assume_role_is_in_scope(self):
        """One assume-role action among others still brings the statement into scope.

        _grants_assume_role uses any(), not all(): a statement granting
        ["sts:AssumeRole", "s3:GetObject"] does grant assume-role. Under all() the statement
        is skipped entirely and an unbound source goes unreported. No other fixture supplies
        a multi-action list mixing an assume-role action with an unrelated one.
        """
        role = _role(
            "mixed-action",
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": SERVICE},
                    "Action": ["sts:AssumeRole", "s3:GetObject"],
                    "Condition": {"StringEquals": {"sts:ExternalId": "abc"}},
                }
            ],
        )
        result = _run([role])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_service_list_with_an_empty_entry_is_still_service_trust(self):
        """A service list containing an empty string still trusts the real service.

        _trusts_service_principal uses any(): one usable entry is enough. Under all() the
        empty string makes the whole list falsy, the statement stops counting as service
        trust, and the unbound source goes unreported.
        """
        role = _role(
            "empty-service-entry",
            [
                _service_statement(
                    {"StringEquals": {"sts:ExternalId": "abc"}},
                    principal={"Service": [SERVICE, ""]},
                )
            ],
        )
        result = _run([role])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_non_string_service_principal_is_not_service_trust(self):
        """A malformed Service entry is not a service principal.

        The predicate is `isinstance(service, str) and service`. Under `or` a non-string
        truthy value -- arbitrary JSON reaches this from a real account -- would be read as
        a trusted service and the role reported, inventing a finding from malformed input.
        """
        role = _role(
            "non-string-service",
            [
                _service_statement(
                    {"StringEquals": {"sts:ExternalId": "abc"}},
                    principal={"Service": [{"unexpected": "object"}]},
                )
            ],
        )
        assert _run([role]) == []

    def test_empty_condition_block_is_wholly_unconditional(self):
        """`{"StringEquals": {}}` pins nothing, so the statement is out of scope.

        _has_enforced_condition tests the block's keys with any(): an empty block yields
        False, which is correct -- a statement with no enforced key is wholly unconditional
        and belongs to iam_role_cross_service_confused_deputy_prevention, not here. Under
        all() an empty block reports True (all() of nothing is True) and this check invents
        a FAIL for a statement it should never have evaluated.
        """
        role = _role(
            "empty-condition-block", [_service_statement({"StringEquals": {}})]
        )
        assert _run([role]) == []

    def test_report_fields(self):
        """The report carries the role's id, ARN, region and tags.

        Pinned once here, since every other case in this file asserts only the status.
        """
        role = _role(
            "reported-role",
            [_service_statement({"ArnLike": {"aws:SourceArn": BUCKET_ARN}})],
        )
        finding = _run([role])[0]
        assert finding.resource_id == "reported-role"
        assert finding.resource_arn == role.arn
        assert finding.region == AWS_REGION_US_EAST_1
        assert finding.resource_tags == []

    def test_every_role_gets_one_finding(self):
        """Three roles get one report each, judged on their own trust policy.

        PASS, FAIL and MANUAL out of a single run. Without this, a check that reported only the
        first role in the account would satisfy every other case in this file, because each one
        passes exactly one role: an account's roles are its most numerous IAM resource, so the
        silently-unreported remainder would be the whole estate bar one.
        """
        roles = [
            _role("scoped", [_service_statement(ACCOUNT_ONLY)]),
            _role(
                "unbound",
                [_service_statement({"ArnLike": {"aws:SourceArn": BUCKET_ARN}})],
            ),
            _role(
                "notaction",
                [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": SERVICE},
                        "NotAction": "s3:*",
                    }
                ],
            ),
        ]
        result = _run(roles)
        assert {report.resource_id: report.status for report in result} == {
            "scoped": "PASS",
            "unbound": "FAIL",
            "notaction": "MANUAL",
        }


class Test_differential_against_existing_sibling_check:
    """Pins the two states iam_role_cross_service_confused_deputy_prevention leaves unreported.

    These assertions describe upstream behaviour, so they hold on master too -- they document
    the gap this check closes rather than the new check's own logic.
    """

    def test_sibling_passes_a_source_arn_that_binds_no_account(self):
        """The sibling reads an accountless SourceArn as protected while this check FAILs it.

        Both halves are asserted in one test, so the gap is demonstrated rather than described. The
        is_policy_public assertion describes upstream behaviour and holds on master too.
        """
        from prowler.providers.aws.services.iam.lib.policy import is_policy_public

        policy = _trust_policy(
            [_service_statement({"ArnLike": {"aws:SourceArn": BUCKET_ARN}})]
        )
        # The sibling reads this as protected (not public) and reports PASS...
        assert (
            is_policy_public(
                policy,
                AWS_ACCOUNT_ID,
                check_cross_service_confused_deputy=True,
                not_allowed_actions=["sts:AssumeRole", "sts:*"],
            )
            is False
        )
        # ...while the bucket ARN binds no account, so this check reports FAIL.
        role = _role("bucket-arn-role", policy["Statement"])
        assert _run([role])[0].status == "FAIL"

    def test_sibling_skips_a_hybrid_principal_entirely(self):
        """The sibling's is_service_role gate rejects hybrid principals, so it reports nothing.

        This check reports the unconfined cross-account assume path instead, which is the second
        state the sibling leaves unreported.
        """
        from prowler.providers.aws.services.iam.iam_service import is_service_role

        hybrid_statement = _service_statement(
            principal={
                "Service": SERVICE,
                "AWS": f"arn:aws:iam::{OTHER_ACCOUNT_ID}:root",
            }
        )
        # is_service_role gates the sibling, and it rejects hybrid principals, so the
        # sibling emits no finding for this role at all...
        assert (
            is_service_role(
                {"AssumeRolePolicyDocument": _trust_policy([hybrid_statement])}
            )
            is False
        )
        # ...while this check reports the unconfined cross-account assume path.
        role = _role("hybrid-role", [hybrid_statement])
        findings = _run([role])
        assert len(findings) == 1
        assert findings[0].status == "FAIL"


class Test_trust_unevaluated_and_wildcard_shapes:
    """Shapes IAM accepts that the check previously read as granting nothing.

    Each one made a role disappear from the population or PASS on an absence, and each is
    reachable: IAM Access Analyzer ValidatePolicy accepts all three.
    """

    def test_assume_role_action_wildcard_is_not_a_pass(self):
        """sts:Assume* reaches AssumeRole while matching no literal in ASSUME_ROLE_ACTIONS.

        An exact membership test dropped the statement from the population, so the role
        PASSed claiming it confines every AWS service principal -- on the strength of a
        statement the check never read.
        """
        # A non-confining condition puts the statement in scope. This check deliberately
        # judges a constraint that IS present rather than its absence -- a wholly
        # unconditional trust is iam_role_cross_service_confused_deputy_prevention's.
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": SERVICE},
            "Action": "sts:Assume*",
            "Condition": {"ArnLike": {"aws:SourceArn": "*"}},
        }
        result = _run([_role("wildcard-action", [statement])])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_leading_whitespace_action_is_not_a_pass(self):
        """IAM tolerates surrounding whitespace; both sibling checks in this PR strip it."""
        # A non-confining condition puts the statement in scope. This check deliberately
        # judges a constraint that IS present rather than its absence -- a wholly
        # unconditional trust is iam_role_cross_service_confused_deputy_prevention's.
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": SERVICE},
            "Action": " sts:AssumeRole",
            "Condition": {"ArnLike": {"aws:SourceArn": "*"}},
        }
        result = _run([_role("padded-action", [statement])])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_star_principal_is_not_silently_skipped(self):
        """Principal "*" is a string, not a mapping, and trusts every principal there is.

        The isinstance guard returned False for it, so the role produced no finding at all --
        neither FAIL nor MANUAL -- which is the worst of the three outcomes.
        """
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }
        result = _run([_role("star-principal", [statement])])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_notaction_trust_statement_is_manual(self):
        """NotAction under Allow can permit sts:AssumeRole while carrying no Action key.

        _grants_assume_role reads only Action, so the statement dropped out and the role
        vanished. Inverting NotAction is more than this check can claim, so it says so.
        """
        statement = {
            "Effect": "Allow",
            "Principal": {"Service": SERVICE},
            "NotAction": "s3:*",
        }
        result = _run([_role("notaction-trust", [statement])])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "NotAction" in result[0].status_extended
