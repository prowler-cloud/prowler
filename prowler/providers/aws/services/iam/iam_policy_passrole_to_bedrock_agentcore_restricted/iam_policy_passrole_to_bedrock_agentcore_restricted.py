import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import iam_pattern_matches

AGENTCORE_SERVICE_PREFIX = "bedrock-agentcore"
AGENTCORE_SERVICE_PRINCIPAL = "bedrock-agentcore.amazonaws.com"
# Bedrock AgentCore also reaches IAM through subdomain principals such as
# runtime-identity.bedrock-agentcore.amazonaws.com, so a literal value in that family
# pins the statement to AgentCore just as the base principal does.
AGENTCORE_PRINCIPAL_FAMILY_PATTERN = re.compile(
    rf"^([a-z0-9-]+\.)?{AGENTCORE_SERVICE_PREFIX}(-[a-z0-9-]+)?\.amazonaws\.com$",
    re.IGNORECASE,
)
# Concrete principals used to ask whether a condition value, READ AS AN IAM PATTERN, covers one of
# them. That is a different question from the regex above, which asks whether the value IS a family
# member, and asking only the second let a wildcard covering the family out of scope entirely. Both
# are needed: the regex catches a literal subdomain nobody enumerated here, and the probes catch a
# pattern that names no principal literally while reaching several.
AGENTCORE_PRINCIPAL_PROBES = (
    AGENTCORE_SERVICE_PRINCIPAL,
    f"runtime-identity.{AGENTCORE_SERVICE_PRINCIPAL}",
)
# Two role names used to ask whether a resource field names EVERY role rather than some of them:
# the shortest a role name can be, and the longest. Only "*" can span an arbitrary run of
# characters -- "?" matches exactly one -- so a pattern built from literals and "?" alone covers a
# bounded set of names and cannot match both probes, while any pattern that does match both leaves
# no role name outside it.
_SHORTEST_ROLE_NAME = "role/a"
_LONGEST_ROLE_NAME = "role/" + "r0le-name-" * 6 + "abcd"  # 64 chars, the IAM maximum
EVERY_ROLE_RESOURCE_PROBES = (_SHORTEST_ROLE_NAME, _LONGEST_ROLE_NAME)
# Operators that COMPARE the request's iam:PassedToService against the statement's own values, so a
# value under one of them names a service this statement can hand a role to. An allow-list, because
# the deny-list this replaced -- two substring tests for "not" and "ifexists" -- dropped the entire
# condition on a one-word operator change, and a dropped condition fell through to the document-wide
# fallback in _targets_agentcore as though the statement pinned nothing at all.
#
# *IfExists and ForAllValues ARE included, unlike _RESTRICTIVE_ATTESTATION_OPERATORS in
# kms/lib/enclave.py which rejects both as vacuous-true when the key is absent. The difference is the
# question being asked: this function asks which services a statement NAMES, not whether the
# statement is restrictive. A value is named whether or not the operator would also admit a request
# that omits the key.
#
# The ARN operators are DELIBERATELY absent, which is why this list is shorter than the trust check's
# and not an oversight in it. iam:PassedToService is a STRING-typed key holding a service principal,
# and AWS documents it as working with the string operators; an ARN operator on it cannot compare
# meaningfully. The trust check needs ArnEquals and ArnLike because aws:SourceArn is ARN-typed. Two
# allow-lists differing by the TYPE of the key they read is correct; differing for no stated reason is
# what gets flagged, so the reason is here.
#
# Consequence worth naming: ArnLikeIfExists on iam:PassedToService contributes no value, so the
# statement takes the no-pin path and reaches every service -- the same route as carrying no condition
# at all. It still FAILs beside an AgentCore action, by that route rather than by being read as a pin.
_PASSED_TO_SERVICE_OPERATORS = frozenset(
    f"{qualifier}{operator}{suffix}".lower()
    for qualifier in ("", "ForAnyValue:", "ForAllValues:")
    for operator in ("StringEquals", "StringEqualsIgnoreCase", "StringLike")
    for suffix in ("", "IfExists")
)


def _as_list(value) -> list:
    """Normalize to list: None -> [], scalar -> [val], list -> list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document: dict) -> list:
    """Extract Statement, normalizing single-statement dict to list."""
    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _covers_passrole(statement: dict) -> bool:
    """Return True if the statement's Action covers iam:PassRole.

    The service field is matched as an IAM pattern rather than compared literally, so
    `*:PassRole` is read as covering it. A bare "*" still does not count: a statement allowing
    every action on every resource is what the administrative-privileges checks report, and
    re-reporting it here would duplicate them instead of adding a claim. The `separator != ":"`
    guard is what preserves that, since "*" partitions to an empty separator.
    """
    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(":")
        # A statement allowing EVERY action is the administrative-privileges checks' finding,
        # whether it is spelled "*" or "*:*"; the separator test covers the bare "*".
        if separator != ":" or (service == "*" and operation == "*"):
            continue
        if not iam_pattern_matches(service, "iam"):
            continue
        if iam_pattern_matches(operation, "PassRole"):
            return True
    return False


def _grants_agentcore_action(document: dict) -> bool:
    """Return True if the policy allows at least one bedrock-agentcore action.

    This is what puts an otherwise service-agnostic PassRole grant in scope: the same
    policy can both create an AgentCore resource and choose the role it runs as. A bare
    "*" is again excluded, so an administrator policy is not pulled in on that basis.

    The service field is matched as an IAM pattern, as it is everywhere else these checks read
    one. It matters most here: `bedrock-*:CreateAgentRuntime` is a plausible thing to write,
    since one prefix covers bedrock and bedrock-agentcore together, and a literal comparison
    read it as no AgentCore reach -- which left an unpinned PassRole grant beside it out of
    scope entirely, so the policy PASSed.
    """
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        for action in _as_list(statement.get("Action")):
            if not isinstance(action, str):
                continue
            service, separator, _ = action.strip().partition(":")
            if separator == ":" and iam_pattern_matches(
                service, AGENTCORE_SERVICE_PREFIX
            ):
                return True
    return False


def _passed_to_service_values(statement: dict) -> list:
    """Collect the services a statement's iam:PassedToService condition names.

    Read through the allow-list above rather than by rejecting operator names. The deny-list this
    replaced skipped every *IfExists spelling, and because _targets_agentcore treats "no values" as
    "reaches every service" and then consults the whole document, skipping the condition inverted
    the verdict in both directions on a one-word change:

    - ``StringEqualsIfExists`` naming AgentCore, on ``Resource: "*"``, produced no values, so a
      policy carrying no other AgentCore action fell out of scope and PASSed -- a PassRole grant on
      every role in the account, cleared by a high-severity privilege-escalation check.
    - ``StringEqualsIfExists`` naming another service produced no values too, so the document-wide
      fallback pulled the statement back in beside any AgentCore action and it FAILed, when a
      statement pinned to sagemaker is out of scope by the same rule spelled ``StringEquals``.

    A negated operator is still not read: it names the services the statement will NOT pass to, and
    the set it does reach is everything else, which is what "no values" already means here.
    """
    values = []
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return values
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _PASSED_TO_SERVICE_OPERATORS:
            continue
        for key, value in block.items():
            if isinstance(key, str) and key.lower() == "iam:passedtoservice":
                values.extend(_as_list(value))
    return values


def _null_guarded_keys(condition: dict) -> set:
    """Return the lowercased condition keys a ``Null: "false"`` test forces to be present.

    The helper the trust check in this PR defines, for the same reason, and byte-identical to it
    EXCEPT for the value type read -- see below, and see that file's docstring for the other half.
    Both spellings are handled, the scalar and the list, as kms/lib/enclave.py does.

    A JSON ``false`` counts as well as the string ``"false"``, because on THIS check's surface IAM
    stores and returns both. Measured on a customer-managed policy, which is exactly this check's
    population: ``create_policy`` with ``{"Null": {"iam:PassedToService": false}}`` is accepted and
    ``get_policy_version`` returns a Python ``bool``, unconverted. Reading only the string made the
    guard invisible, so a pin AWS's own simulator holds to one service -- absent key
    ``implicitDeny``, AgentCore ``implicitDeny`` -- was reported as passing every role to AgentCore.
    That is the AWS-prescribed hardening, and the check FAILed it.

    The trust sibling stays string-only ON PURPOSE, because a trust policy normalizes its scalars
    and no bool can reach it: the divergence is measured, not drift.

    This also DIVERGES from kms/lib/enclave.py deliberately: that copy tests ``isinstance(value,
    str)`` only and carries the same blind spot. Diverging toward the correct reading rather than
    inheriting the house copy's defect.

    EVERY value must be ``false``, not merely one of them, because IAM ORs the values inside a single
    condition operator. ``Null: {key: ["true","false"]}`` therefore means "key absent OR key present",
    which is always true and binds NOTHING, yet reading it with ``any`` credited it as a guard and
    rescued a defeasible pin -- so ADDING the word ``true`` to a guard list improved the score.
    Measured on IAM's own evaluator with the key omitted: ``allowed`` for ``["true","false"]`` and
    ``["false","true"]``, indistinguishable from carrying no Null block, against ``implicitDeny`` for
    ``"false"``, ``["false"]`` and ``["false","false"]``. Reachable: ``create_policy`` stores a
    multi-value list and ``get_policy_version`` returns it unchanged, and the trust surface preserves
    a multi-element list too even though it collapses a single-element one to a scalar.

    The ``candidates and`` guard is not decoration: ``all()`` over an empty list is True, so an empty
    value list would otherwise be read as the strongest possible guard.

    ``0`` is NOT a guard, and it is the VALUE comparison that excludes it, not the type test:
    ``str(0)`` is ``"0"``, which is simply not ``"false"``. The ``isinstance`` merely narrows the
    accepted types to the two JSON scalars IAM actually returns here. Spelled out because the
    tempting formulation is the broken one -- ``not candidate`` or ``candidate is False`` reads
    ``0``, ``""``, ``None`` and ``[]`` as guards, since ``isinstance(False, int)`` is True in Python
    and falsiness is not the question being asked.

    ACCESS ANALYZER DOES NOT CORROBORATE THIS BOUNDARY, and an earlier version of this docstring
    claimed it did. Measured: it reports TYPE_MISMATCH_BOOLEAN for ``"FALSE"`` and for ``" false "``,
    both of which this helper CREDITS, as well as for ``0``, which it does not. So its type-checking is
    stricter than this helper's casing tolerance in both directions, and the boundary drawn here is
    this check's own decision rather than an external one. Over-recognising is the dangerous direction,
    because crediting a guard turns a FAIL into a PASS.
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
                isinstance(candidate, (str, bool))
                and str(candidate).strip().lower() == "false"
                for candidate in candidates
            ):
                guarded.add(key.lower())
    return guarded


def _passed_to_service_pin_is_defeasible(statement: dict) -> bool:
    """Return True if every operator naming iam:PassedToService can be skipped by the caller.

    An *IfExists operator is not evaluated when the request omits the key, and ForAllValues is
    vacuous-true for an absent key -- kms/lib/enclave.py records these as the same trap. So a
    statement whose only pin is one of those reaches every service as well as the one it names,
    and cannot be treated as confined to it.

    UNLESS the same statement carries ``Null: "false"`` on the same key, which forces the key to be
    present and removes the skip. That rescue was applied to the trust check's collector in this PR
    and never here, so a statement written the way AWS prescribes -- "You should always include the
    Null condition operator ... with a false value" -- was read as unconfined and the policy FAILed.
    It penalised the hardened spelling: adding the guard to a pinned statement changed nothing, and
    a caller cannot omit a key the guard requires.

    Conditions are ANDed, so one non-defeasible operator naming the key holds the request to that
    key's values whatever else the statement carries; the pin is defeasible only if all of them are.
    """
    defeasible = []
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False
    guarded = "iam:passedtoservice" in _null_guarded_keys(condition)
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _PASSED_TO_SERVICE_OPERATORS:
            continue
        if not any(
            isinstance(key, str) and key.lower() == "iam:passedtoservice"
            for key in block
        ):
            continue
        defeasible.append(
            (
                lowered_operator.endswith("ifexists")
                or lowered_operator.startswith("forallvalues:")
            )
            and not guarded
        )
    return bool(defeasible) and all(defeasible)


def _names_agentcore(values: list) -> bool:
    """Return True if any value can name an AgentCore service principal.

    Two questions, and asking only the second was a false PASS on the exact grant this check exists
    to catch. Probing the value as a pattern against the ONE base principal, plus a regex asking
    whether the value IS a family member, left every wildcard that COVERS the family unrecognised:

      *.bedrock-agentcore.amazonaws.com          covers 2 known principals   read as another service
      *-identity.bedrock-agentcore.amazonaws.com covers runtime-identity     read as another service
      runtime-identity.*                         covers runtime-identity     read as another service
      *.bedrock-agentcore.*                      covers 2                    read as another service

    Each was treated as pinning iam:PassedToService to something other than AgentCore, so the
    statement left scope and the policy PASSed -- while both the narrower literal and the
    no-condition case FAIL. Broadening the grant flipped the verdict the safe way round, which is
    the shape that never self-corrects.

    So the value is now matched as a pattern against several concrete principals, not one, and a
    literal outside that list is still caught by the family regex. ``?`` covers nothing here on
    purpose: it matches exactly one character and no principal has a single-character subdomain --
    that ``?`` cannot match zero characters is pinned by iam/lib/policy_test.py, not assumed here.
    """
    return any(
        isinstance(value, str)
        and (
            AGENTCORE_PRINCIPAL_FAMILY_PATTERN.match(value.strip())
            or any(
                iam_pattern_matches(value, probe)
                for probe in AGENTCORE_PRINCIPAL_PROBES
            )
        )
        for value in values
    )


def _targets_agentcore(statement: dict, document: dict) -> bool:
    """Return True if the statement can hand a role to Bedrock AgentCore.

    Three cases, in the order they are decided:

    1. A condition NAMES AgentCore. The statement is in scope on its own terms, under any operator
       that compares the key -- including *IfExists, which used to be dropped before the value was
       ever read. That drop is what let a PassRole grant on every role in the account PASS: with no
       values the statement looked unpinned, so scope fell to a document that allowed no AgentCore
       action, and the check cleared it.
    2. A condition pins the key elsewhere and cannot be skipped. The statement cannot reach
       AgentCore however the rest of the policy is shaped, so it is out of scope -- this is what
       keeps a grant pinned to sagemaker.amazonaws.com out of the check.
    3. Anything else -- no condition on the key, or only a defeasible one -- reaches every service,
       so the rest of the policy decides: in scope when the policy also allows an AgentCore action.
    """
    values = _passed_to_service_values(statement)
    if _names_agentcore(values):
        return True
    if values and not _passed_to_service_pin_is_defeasible(statement):
        return False
    return _grants_agentcore_action(document)


def _names_every_role(resource: str) -> bool:
    """Return True if this one resource names every role rather than specific roles.

    Decided by matching the resource against the shortest and longest role name a pattern would
    have to cover, rather than by a regex demanding the resource field be a run of asterisks. That
    regex was both too narrow and, being anchored on a literal ``arn:``, blind to a wildcarded
    partition. Four resources naming every role in the account read as specific ones:

      role/?*   every role whose name has at least one character
      *role*    every role/... resource there is, since the stars absorb the prefix and the name
      arn:aws:iam::*                 the star spans the account and resource fields
      *:aws:iam::123456789012:role/* a leading star matches "arn"

    ``role/?`` still passes and is the case that shows the rule is not "contains a metacharacter":
    ``?`` matches exactly one character -- pinned by iam/lib/policy_test.py rather than assumed here
    -- so it names single-character roles and nothing else. A name
    prefix such as ``role/AgentCoreEvaluationRole*`` passes for the same reason -- it covers a set,
    but not every role -- and that is the scope AWS's own AgentCore Evaluations reference policy
    uses, so reporting it would report the documented configuration.

    Residual, and it is a judgement not a hole: a pattern of exactly 64 ``?`` would match the long
    probe and not the short one, so it reads as specific. It names every role whose name is exactly
    64 characters, which is a set no operator writes by hand.

    A pattern with fewer than six fields is decided structurally, and NOT by probing concrete ARNs.
    Probing pinned the partition and account, so the six-field branch ignored both while the short
    branch did not: ``arn:aws:iam::555555555555*`` was read as specific while the identical shape in
    the probe's own account FAILed, and ``arn:aws-us-gov:iam::*`` and ``arn:aws-cn:iam::*`` were
    read as specific because no probe carried those partitions. No probe corpus fixes an account
    PREFIX -- there is nothing to enumerate. So: a star in the LAST spelled-out field spans every
    field after it, because IAM wildcards match the colon, and what remains is that the fields
    actually spelled out must be able to name a role ARN.

    Two positions get an extra test, and both rest on a fixed property of an IAM ARN rather than on a
    corpus:

      account (5 fields)  an account is twelve digits, so a literal head that is not digits names no
                          account. This is what keeps ``arn:aws:iam::role/Prod*`` specific.
      region  (4 fields)  every IAM ARN has an EMPTY region, so ANY literal head there names no
                          region. This is what keeps ``arn:aws:iam:role/Prod*`` specific -- the same
                          shape one colon short, which without this test read as naming every role
                          and drew a FAIL on a pattern matching no role ARN at all.

    ``arn:aws:iam:*`` and ``arn:aws:iam:?*`` still name every role, because their literal head is
    empty once ``?`` is discounted, and ``?`` matches the colon.

    The PARTITION position deliberately gets no such test, which is why ``arn:xyz*`` still reads as
    naming every role. A partition is not a fixed shape -- ``aws``, ``aws-cn``, ``aws-us-gov`` and the
    iso partitions differ -- and a PREFIX of one cannot be enumerated, which is the same reason the
    probe corpus was abandoned above. Over-reporting an unspellable partition is the safe direction
    for a privilege-escalation check; guessing the partition set is not.
    """
    candidate = resource.strip()
    if candidate == "*":
        return True
    arn_fields = candidate.split(":", 5)
    if len(arn_fields) < 6:
        if "*" not in arn_fields[-1]:
            return False
        if not iam_pattern_matches(arn_fields[0], "arn"):
            return False
        if len(arn_fields) > 2 and not iam_pattern_matches(arn_fields[2], "iam"):
            return False
        if len(arn_fields) == 4:
            # The last field sits in the REGION position, and every IAM ARN has an EMPTY region. Any
            # literal head -- role/Prod in arn:aws:iam:role/Prod* -- can name no region, so the
            # pattern matches no role ARN however its star spans. Discounting ? keeps
            # arn:aws:iam:?* naming every role, since ? matches the colon.
            region_head = arn_fields[3].split("*", 1)[0].replace("?", "")
            if region_head:
                return False
        if len(arn_fields) == 5:
            # The last field sits in the ACCOUNT position, and an account is twelve digits. A
            # literal head that is not digits -- role/Prod in arn:aws:iam::role/Prod* -- can name no
            # account, so the pattern matches no role ARN however its star spans.
            account_head = arn_fields[4].split("*", 1)[0].replace("?", "")
            if account_head and not account_head.isdigit():
                return False
        return True
    if not iam_pattern_matches(arn_fields[0], "arn"):
        return False
    if not iam_pattern_matches(arn_fields[2], "iam"):
        return False
    return all(
        iam_pattern_matches(arn_fields[5], probe)
        for probe in EVERY_ROLE_RESOURCE_PROBES
    )


def _allows_any_role(statement: dict) -> bool:
    """Return True if the statement's resources name every role rather than named roles."""
    resources = _as_list(statement.get("Resource"))
    if not resources:
        # NotResource grants every resource but the excluded ones, so every role outside
        # that list stays passable.
        return "NotResource" in statement
    return any(
        isinstance(resource, str) and _names_every_role(resource)
        for resource in resources
    )


def _deny_removes_passrole(statement: dict) -> bool:
    """Return True if a DENY statement's Action removes iam:PassRole.

    Separate from _covers_passrole on purpose, because the bare-star exclusion that is right on the
    Allow side inverts on the Deny side. There, skipping ``*`` and ``*:*`` avoids duplicating the
    administrative-privileges checks; here it meant an unconditional Deny of EVERY action credited
    nothing, so a policy that grants no PassRole at all was reported FAIL. The Allow-side guard is
    deliberately left alone: relaxing it would reverse the settled decision that admin-level grants
    belong to those checks.

    Deny expressed as NotAction is still NOT read. Inverting it needs the whole action namespace,
    and not crediting it errs toward reporting rather than toward silence.
    """
    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(":")
        if separator != ":":
            # A bare "*" denies every action, iam:PassRole among them.
            if service == "*":
                return True
            continue
        if not iam_pattern_matches(service, "iam"):
            continue
        if iam_pattern_matches(operation, "PassRole"):
            return True
    return False


def _denies_passrole_everywhere(document: dict) -> bool:
    """Return True if an unconditional Deny removes iam:PassRole on every resource."""
    for statement in _statements(document):
        if statement.get("Effect") != "Deny" or statement.get("Condition"):
            continue
        if not _deny_removes_passrole(statement):
            continue
        if any(
            isinstance(resource, str) and resource.strip() == "*"
            for resource in _as_list(statement.get("Resource"))
        ):
            return True
    return False


def _has_unevaluated_notaction(document: dict) -> bool:
    """True if an Allow statement expresses its actions as NotAction.

    NotAction under Effect Allow grants everything EXCEPT what it lists, so a policy using
    it can grant iam:PassRole while carrying no Action key at all. Reading only Action would
    find nothing and report a clean policy. Inverting NotAction correctly means resolving it
    against the full action namespace and its interaction with Resource and NotResource,
    which is more than this check can honestly claim to do -- so the statement is declared
    unevaluated rather than guessed at.
    """
    for statement in _statements(document):
        if statement.get("Effect") == "Allow" and "NotAction" in statement:
            return True
    return False


class iam_policy_passrole_to_bedrock_agentcore_restricted(Check):
    """Check whether a customer-managed policy scopes iam:PassRole to Bedrock AgentCore.

    A statement granting ``iam:PassRole`` on every role beside any Bedrock AgentCore action lets the
    holder hand an arbitrary role to an agent runtime and assume its permissions, which is a
    privilege-escalation path. FAIL when the PassRole resource names every role; PASS when it names
    a bounded set, when the statement pins ``iam:PassedToService`` to another service, or when no
    AgentCore action accompanies it; MANUAL when the policy document could not be read.

    Caveats:
        Customer-managed policies only, since inline policies are covered by the
        ``iam_inline_policy_*`` checks and an AWS-managed policy cannot be edited to remediate a
        finding. A bare ``Action: "*"`` is left to the administrative-privileges checks. Conditions
        do not rescue an unbounded resource, because ``iam:PassedToService`` binds the service and
        ``iam:AssociatedResourceArn`` the consuming resource, neither the set of roles.
    """

    def execute(self) -> Check_Report_AWS:
        """Flag policies allowing PassRole to AgentCore on all roles."""
        findings = []
        for policy in iam_client.policies.values():
            # Only customer-managed policies: the inline population is a separate check,
            # and an AWS-managed policy cannot be edited to remediate a finding.
            if policy.type != "Custom":
                continue
            if not policy.attached and not iam_client.provider.scan_unused_services:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
            report.region = iam_client.region

            if not policy.document:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Custom Policy {policy.name} could not be evaluated because its "
                    "policy document was not retrieved."
                )
                findings.append(report)
                continue

            if _has_unevaluated_notaction(policy.document):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Custom Policy {policy.name} expresses an Allow statement with "
                    "NotAction, which this check does not evaluate, so whether it allows "
                    "iam:PassRole could not be determined; review it manually."
                )
                findings.append(report)
                continue

            unrestricted = False
            if not _denies_passrole_everywhere(policy.document):
                unrestricted = any(
                    statement.get("Effect") == "Allow"
                    and _covers_passrole(statement)
                    and _allows_any_role(statement)
                    and _targets_agentcore(statement, policy.document)
                    for statement in _statements(policy.document)
                )

            if unrestricted:
                report.status = "FAIL"
                report.status_extended = (
                    f"Custom Policy {policy.name} allows iam:PassRole to Bedrock AgentCore "
                    "on every role instead of the specific execution roles AgentCore is "
                    "meant to run as."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Custom Policy {policy.name} does not allow iam:PassRole to Bedrock "
                    "AgentCore on every role."
                )
            findings.append(report)

        return findings
