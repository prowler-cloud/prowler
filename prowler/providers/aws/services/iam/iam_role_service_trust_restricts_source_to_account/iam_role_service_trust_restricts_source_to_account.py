import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import iam_pattern_matches

ASSUME_ROLE_ACTION = "sts:AssumeRole"
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
ORGANIZATION_ID_PATTERN = re.compile(r"^o-[a-z0-9]{10,32}$")
ORGANIZATION_PATH_PATTERN = re.compile(r"^o-[a-z0-9]{10,32}/")


def _as_list(value) -> list:
    """Normalize to list: None -> [], scalar -> [val], list -> list.

    The same helper both sibling checks in this PR define. A present-but-null key -- ``"Action":
    null`` -- makes ``.get("Action", [])`` return None rather than the default, and iterating that
    raises TypeError out of execute(), discarding every finding for the account rather than one
    role. IAM will not store such a document, so this is consistency with the siblings and not a
    security fix.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _grants_assume_role(statement: dict) -> bool:
    """Return True if the statement's Action covers sts:AssumeRole.

    Exactly that one operation, not the wider assume-role family. ``sts:AssumeRoleWithWebIdentity``
    and ``sts:AssumeRoleWithSAML`` are how a federated or web identity assumes a role; an AWS service
    principal uses ``sts:AssumeRole``, so a statement granting only one of the other two is not a
    service-principal trust grant and is correctly outside this check's population.

    The direction matters and is easy to read backwards: the statement's Action is the PATTERN and
    ``sts:AssumeRole`` is the value, so ``sts:*`` and ``sts:Assume*`` match while
    ``sts:AssumeRoleWithSAML`` does not.

    Matched with the shared IAM matcher this PR already ships, rather than a literal tuple plus a
    trailing-star test. That pair recognised sts:AssumeRole, sts:* and * and any prefix ending in a
    star, but nothing else IAM honours: sts:*Role, sts:A*Role, sts:Assume?ole and sts:AssumeRol?
    each grant the action and each produced NO REPORT at all, because a statement that does not
    grant assume-role drops out of the evaluated population. Beside a second statement the same
    miss was worse than silence -- the role reported PASS, asserting it confines every AWS service
    principal in its trust policy to a specific account.
    """
    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue
        if iam_pattern_matches(action, ASSUME_ROLE_ACTION):
            return True
    return False


def _trusts_service_principal(statement: dict) -> bool:
    """Return True if the statement trusts at least one AWS service principal.

    A statement that trusts a service principal *alongside* other principal types
    still qualifies: the service principal is reachable regardless of what else the
    statement trusts, so it needs the same confused-deputy scoping.
    """
    principal = statement.get("Principal", {})
    if not isinstance(principal, dict):
        # Principal: "*" is a string, not a mapping, and trusts every principal there is --
        # including every service principal. Returning False here dropped the statement from
        # the population and the role produced no finding at all.
        return principal == "*"
    return any(
        isinstance(service, str) and service
        for service in _as_list(principal.get("Service"))
    )


# Operators that COMPARE a request value against the statement's own, so a value under one of them
# genuinely pins the request source. An allow-list, because the deny-list this replaced -- two
# substring tests for "not" and "ifexists" -- admitted every operator it did not recognise, Null
# among them. Modelled on _RESTRICTIVE_ATTESTATION_OPERATORS in kms/lib/enclave.py, which solved the
# same problem for attestation keys; the Arn forms are added here because aws:SourceArn is compared
# with them. Matched lowercased, which keeps an oddly-cased operator as admissible as it was before.
# The IfExists suffix is included, and admitted only under the same Null:"false" guard ForAllValues
# needs. kms/lib/enclave.py calls it "the same trap as ForAllValues without a Null:false guard", so
# rejecting one outright while rescuing the other was inconsistent on that file's own reading; and
# secretsmanager_has_restrictive_resource_policy already ships IfExists paired with Null as its
# accepted restrictive form, so the pairing is a shape prowler recognises rather than a new rule.
_COMPARING_CONDITION_OPERATORS = frozenset(
    f"{qualifier}{operator}{suffix}".lower()
    for qualifier in ("", "ForAnyValue:", "ForAllValues:")
    for suffix in ("", "IfExists")
    for operator in (
        "StringEquals",
        "StringEqualsIgnoreCase",
        "StringLike",
        "ArnEquals",
        "ArnLike",
    )
)


def _null_guarded_keys(condition: dict) -> set:
    """Return the lowercased condition keys a ``Null: "false"`` test forces to be present.

    Both spellings are handled, the scalar and the list, as kms/lib/enclave.py does.

    EVERY value must be ``false``, not merely one of them, because IAM ORs the values inside a single
    condition operator. ``Null: {key: ["true","false"]}`` means "key absent OR key present", which is
    always true and binds NOTHING, yet ``any`` credited it and rescued a defeasible pin. This axis is
    shared with the PassRole sibling and fixed identically there, because a MULTI-element list survives
    on this surface: ``create_role`` stores ``["true","false"]`` and ``get_role`` returns it as a list.
    A single-element ``["false"]`` is collapsed to the scalar ``"false"`` here, which is why only the
    multi-value spelling matters. ``candidates and`` is load-bearing: ``all()`` over an empty list is
    True, so an empty value list would read as the strongest possible guard.

    TWO AXES, MEASURED SEPARATELY, AND THEY DIVERGE. On VALUE TYPE this stays string-only while the
    PassRole sibling also reads a JSON boolean, because a trust policy normalizes scalar types and no
    bool can reach here. On LIST ARITY the two agree, because a multi-element list is preserved on both
    surfaces. Both halves are stated at both ends rather than left to look like drift, since a helper
    pair that agrees on one axis and differs on another is exactly what decays when nobody wrote down
    which axis was which.

    A trust policy NORMALIZES its condition scalars, measured both ways round: ``create_role`` with
    ``{"Null": {"aws:SourceAccount": false}}`` is ACCEPTED, and the document comes back carrying the
    string ``"false"`` -- from ``list_roles``, which is the call this check's collector actually
    makes, and identically from ``get_role``. An unquoted ``123456789012`` comes back quoted too.
    So no bool or int can reach this helper, and reading one would be dead code with no fixture able
    to exercise it. A customer-managed POLICY document, which is all the sibling reads,
    PRESERVES both types instead -- two IAM surfaces, two behaviours, which is exactly why this was
    measured per surface rather than inferred from one.

    If IAM ever stops normalizing here, take the sibling's reading: ``isinstance(candidate, (str,
    bool)) and str(candidate).strip().lower() == "false"``. That admits a JSON ``false`` and still
    excludes ``0``, because ``str(0)`` is ``"0"`` -- the value comparison does that work, not the
    type test. What it must not become is ``not candidate`` or ``candidate is False``, which read
    ``0``, ``""``, ``None`` and ``[]`` as guards; ``isinstance(False, int)`` is True in Python and
    falsiness is not the question. Over-recognising a guard turns a FAIL into a PASS.
    """
    guarded = set()
    for operator, block in condition.items():
        if not isinstance(operator, str) or operator.lower() != "null":
            continue
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not isinstance(key, str):
                continue
            candidates = value if isinstance(value, list) else [value]
            if candidates and all(
                isinstance(candidate, str) and candidate.strip().lower() == "false"
                for candidate in candidates
            ):
                guarded.add(key.lower())
    return guarded


def _enforced_condition_value_groups(statement: dict, condition_key: str) -> list:
    """Collect the values a statement pins to condition_key, GROUPED BY OPERATOR.

    One group per operator, because IAM ANDs the operators in a Condition while ORing the values
    inside one operator. The grouping follows that structure directly:

    - ACROSS groups, a caller asks whether ANY ONE confines the source. If one operator holds the
      request to literal account IDs, the request is confined whatever else it must also satisfy --
      an ANDed operator can only narrow. Pooling operators together would let a broad ``StringLike``
      beside a pinned ``StringEquals`` widen the verdict, which inverts the semantics.
    - WITHIN a group, EVERY value must qualify, since IAM lets the request match any one of them.

    This is the per-operator evaluation ``kms/lib/enclave.py`` performs.

    Operators are taken from an ALLOW-LIST, not a deny-list, so an operator this code does not
    recognise is never credited. Two consequences worth naming:

    - Negated operators invert the match and so pin the source to nothing. They are absent from the
      allow-list by design.
    - ``Null`` is a presence test rather than a comparison, so it never contributes a value here. Its
        role is only as the guard below. A deny-list would admit it and feed the literal string
        ``"false"`` in as though it were an account ID.

    TWO operator families are vacuous on an Allow, and both are credited only under the same guard:

    - ``ForAllValues:*`` "returns true if there are no context keys in the request", which AWS
      documents with an explicit warning against using it with an Allow effect. This check evaluates
      Allow statements only, so that is the reachable case.
    - ``*IfExists`` is not evaluated at all when the request omits the key, which kms/lib/enclave.py
      names as "the same trap as ForAllValues without a Null:false guard".

    Both are credited only when the same statement carries a ``Null: "false"`` guard on the SAME key,
    which forces the key to be present and removes the vacuity. The guard defeats it identically for
    every spelling, so all four of ``ForAllValues:StringEquals``, ``StringEqualsIfExists``,
    ``ArnLikeIfExists`` and ``ForAllValues:StringLikeIfExists`` are treated alike --
    ``secretsmanager_has_restrictive_resource_policy`` already ships IfExists paired with Null as its
    accepted restrictive form. Refusing the guarded spellings outright would also be wrong because
    ``aws:SourceOrgPaths`` is multivalued, making a set operator the only correct way to write it.

    ``ForAnyValue:*`` needs no guard. AWS documents that for no matching context key, or if the key
    does not exist, it returns false -- so it fails closed on an Allow.
    """
    groups = []
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return groups
    null_guarded = _null_guarded_keys(condition)
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _COMPARING_CONDITION_OPERATORS:
            continue
        group = []
        for key, value in block.items():
            if not isinstance(key, str) or key.lower() != condition_key:
                continue
            if (
                lowered_operator.startswith("forallvalues:")
                or lowered_operator.endswith("ifexists")
            ) and key.lower() not in null_guarded:
                continue
            group.extend(value if isinstance(value, list) else [value])
        if group:
            groups.append(group)
    return groups


def _pins_every_value(statement: dict, condition_key: str, qualifies) -> bool:
    """Return True if some one operator holds condition_key to values that all qualify."""
    return any(
        all(qualifies(value) for value in group)
        for group in _enforced_condition_value_groups(statement, condition_key)
    )


def _is_account_id(value) -> bool:
    """Return True if the value is a literal 12-digit account ID."""
    return isinstance(value, str) and bool(ACCOUNT_ID_PATTERN.match(value))


def _pins_source_account(statement: dict) -> bool:
    """Return True if aws:SourceAccount is pinned to literal account IDs only."""
    return _pins_every_value(statement, "aws:sourceaccount", _is_account_id)


def _arn_carries_account(value) -> bool:
    """Return True if the ARN's account field is a literal account ID.

    An ARN whose account field is absent (an S3 bucket ARN) or wildcarded does not
    confine the caller to one account, so aws:SourceAccount is still required.
    """
    if not isinstance(value, str):
        return False
    arn_fields = value.split(":")
    return len(arn_fields) >= 5 and _is_account_id(arn_fields[4])


def _pins_source_arn_to_account(statement: dict) -> bool:
    """Return True if some one operator holds every aws:SourceArn value to an account."""
    return _pins_every_value(statement, "aws:sourcearn", _arn_carries_account)


def _pins_source_organization(statement: dict) -> bool:
    """Return True if the source is pinned to an organization or an OU path.

    AWS documents aws:SourceOrgID and aws:SourceOrgPaths as confused-deputy mitigations
    in their own right, so an organization-scoped statement is not reported.
    """
    return _pins_every_value(
        statement,
        "aws:sourceorgid",
        lambda value: isinstance(value, str)
        and bool(ORGANIZATION_ID_PATTERN.match(value)),
    ) or _pins_every_value(
        statement,
        "aws:sourceorgpaths",
        lambda value: isinstance(value, str)
        and bool(ORGANIZATION_PATH_PATTERN.match(value)),
    )


def _prevents_confused_deputy(statement: dict) -> bool:
    """Return True if the statement carries a control AWS documents for *cross-service*
    confused-deputy prevention.

    sts:ExternalId is deliberately absent. AWS documents it only for third-party access --
    an external ID is a value the third party supplies -- and an AWS service passes source
    account and source ARN context, never an external ID. Crediting it here would accept a
    control the calling service can never satisfy.
    """
    return (
        _pins_source_account(statement)
        or _pins_source_arn_to_account(statement)
        or _pins_source_organization(statement)
    )


def _has_enforced_condition(statement: dict) -> bool:
    """Return True if the statement gates access on at least one enforced condition key.

    A statement with no enforced condition at all places no constraint whatsoever on the
    caller. That wholly-unconditional state is a different (and more severe) posture than
    a constraint that is present but does not confine the source, and it is what
    iam_role_cross_service_confused_deputy_prevention reports.

    This filter DELIBERATELY differs from the allow-list _enforced_condition_value_groups applies, and
    the two must not be unified. This one asks only whether the statement is gated at all, so a
    ``Null`` presence test counts: it does gate access, even while binding the source to nothing.
    Pulling such a statement into scope is the safe direction -- it gets evaluated and reported
    rather than silently skipped. The other function asks what the statement PINS, where a presence
    test contributes no value and crediting one poisoned the shape test beside it.
    """
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if "not" in lowered_operator or lowered_operator.endswith("ifexists"):
            continue
        if any(isinstance(key, str) for key in block):
            return True
    return False


def _is_plain_service_trust_policy(statements: list) -> bool:
    """Return True if every statement is an Allow of assume-role to services only.

    This is the trust-policy shape that the existing service-role checks assume. A policy
    that departs from it -- by carrying a Deny statement, an action outside the
    assume-role family such as sts:SetContext, or a non-service principal -- falls outside
    their evaluated population entirely, so its service principals go unassessed.
    """
    for statement in statements:
        if not isinstance(statement, dict):
            return False
        if statement.get("Effect") != "Allow" or not _grants_assume_role(statement):
            return False
        principal = statement.get("Principal", {})
        if not isinstance(principal, dict) or set(principal.keys()) != {"Service"}:
            return False
    return True


class iam_role_service_trust_restricts_source_to_account(Check):
    """Check whether a role's service-principal trust confines the request to a source account.

    An AWS service principal permitted to assume a role without a source-account or source-ARN
    binding exposes the role to the confused-deputy problem: another customer's resource can induce
    the service to assume it. FAIL when a trust statement carries a condition that confines nothing;
    PASS when every in-scope statement binds a source; MANUAL for a statement using ``NotAction``,
    which is the one shape here that cannot be evaluated, since inverting it correctly is more than
    this check can claim. A trust policy is always present on a role, so there is no unreadable-document
    branch on this surface, unlike the two policy checks beside it.

    Caveats:
        Companion to ``iam_role_cross_service_confused_deputy_prevention`` rather than a replacement.
        That check reports statements with no restrictive condition at all, on roles it classifies as
        service roles; this one asserts the clause it leaves open, so the wholly unconditional
        statement produces no finding here and the two can both report one role. Bindings are read
        from Allow statements only, so a trust policy confined solely through a Deny is still
        reported.
    """

    def execute(self) -> Check_Report_AWS:
        """Flag service-principal trust whose present condition binds no account.

        Account bindings are read from Allow statements ONLY. A Deny can also confine the source --
        `StringNotEquals` on `aws:SourceAccount` denies every account but one -- and this check does
        not evaluate that, so a trust policy confined solely through a Deny is reported even though
        it is confined. Rare, and it errs toward reporting rather than toward silence, but it is an
        unevaluated shape and is declared here rather than left to be inferred, as `NotAction`
        already is. A Deny still matters for scope: it takes the policy outside the plain-service
        shape the sibling checks assume, which is what brings the Allow statements beside it into
        this check's population.

        MANUAL is used deliberately for the NotAction shape, and is not off-contract: 110 upstream
        checks emit it and `lib/check/models.py` places no restriction on it. THE COST, recorded so it
        is not rediscovered: `lib/outputs/asff/asff.py` SKIPS MANUAL findings, since MANUAL is not a
        valid Security Hub compliance state, so a Security Hub consumer sees NOTHING for a trust policy
        this check could not evaluate, and absence there reads as compliance. CSV and OCSF keep the
        status. The sibling token-wildcard check carries the same note, for the same reason.
        """
        findings = []
        for role in iam_client.roles:
            # Service-linked roles are excluded: their trust relationship is managed by
            # the service and cannot be edited, so a finding would not be actionable.
            if "aws-service-role" in role.arn:
                continue

            trust_policy = role.assume_role_policy or {}
            statements = trust_policy.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            # NotAction under Effect Allow grants everything except what it lists, so a
            # trust statement using it can permit sts:AssumeRole while carrying no Action
            # key. _grants_assume_role reads only Action, so such a statement would drop out
            # of service_statements below and the role would produce no finding at all.
            # Inverting NotAction correctly is more than this check can claim, so the role
            # is declared unevaluated rather than silently skipped.
            if any(
                isinstance(statement, dict)
                and statement.get("Effect") == "Allow"
                and "NotAction" in statement
                for statement in statements
            ):
                report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                report.region = iam_client.region
                report.status = "MANUAL"
                report.status_extended = (
                    f"IAM Role {role.name} has a trust policy statement using NotAction, "
                    "which this check does not evaluate, so whether a service principal is "
                    "confined to this account could not be determined; review it manually."
                )
                findings.append(report)
                continue

            service_statements = [
                statement
                for statement in statements
                if isinstance(statement, dict)
                and statement.get("Effect") == "Allow"
                and _grants_assume_role(statement)
                and _trusts_service_principal(statement)
            ]
            if not service_statements:
                continue

            # A wholly unconditional service-principal trust statement on an otherwise
            # plain service role is the fully-unprotected posture that
            # iam_role_cross_service_confused_deputy_prevention already reports. This
            # check asserts the narrower clause it does not: that a constraint which IS
            # present actually confines the source to an account. Statements are therefore
            # in scope when they carry an enforced condition, or when the trust policy
            # departs from the plain-service shape and so is evaluated by no other check.
            is_plain = _is_plain_service_trust_policy(statements)
            in_scope = [
                statement
                for statement in service_statements
                if _has_enforced_condition(statement) or not is_plain
            ]
            if not in_scope:
                continue

            unscoped = [
                statement
                for statement in in_scope
                if not _prevents_confused_deputy(statement)
            ]

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region
            if unscoped:
                # The finding says no condition PINS the key to a literal of the right shape, not
                # that the statement sets no key. Most inputs reaching here do set one: StringLike
                # aws:SourceAccount "1234*", an unguarded ForAllValues, and Null "false" all set the
                # key while pinning nothing. The weaker claim is the one the code supports.
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Role {role.name} trusts an AWS service principal without confining the "
                    "request source, since no condition pins aws:SourceAccount to a literal "
                    "account ID, aws:SourceArn to an ARN carrying one, or aws:SourceOrgID or "
                    "aws:SourceOrgPaths to an organization."
                )
            elif all(
                _pins_source_account(statement)
                or _pins_source_arn_to_account(statement)
                for statement in in_scope
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Role {role.name} confines every AWS service principal in its trust "
                    "policy to a specific account."
                )
            else:
                # The organization route reaches PASS through _pins_source_organization, and an
                # organization may hold hundreds of accounts. Reporting it with the sentence above
                # told the operator something categorically stronger than was verified, so the two
                # postures get separate sentences: a reader needs to know which one they have.
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Role {role.name} confines every AWS service principal in its trust "
                    "policy, but at least one statement is scoped to an organization rather than "
                    "to a single account, so the trusted source may be any account within it."
                )
            findings.append(report)

        return findings
