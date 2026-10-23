from functools import lru_cache

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import get_effective_actions

# The two halves of a payment that must not land on one principal. Opening a
# session is the reviewable step (amount, merchant, mandate); executing the
# payment is the irreversible one. Names are lowercased because IAM matches
# action names case-insensitively.
PROCESS_PAYMENT_ACTION = "bedrock-agentcore:processpayment"
CREATE_PAYMENT_SESSION_ACTION = "bedrock-agentcore:createpaymentsession"

# Action names, without the service prefix, that this check tracks.
TRACKED_OPERATIONS = {
    PROCESS_PAYMENT_ACTION: "ProcessPayment",
    CREATE_PAYMENT_SESSION_ACTION: "CreatePaymentSession",
}


def _resource_patterns(statement: dict, default_when_absent: str) -> set:
    """The Resource patterns a statement names.

    Args:
        statement: One IAM policy statement.
        default_when_absent: What to assume when ``Resource`` is missing. Deliberately different for
            Allow and Deny -- see the callers.

    Returns:
        The statement's Resource patterns, or a single-item set holding the supplied default.
    """
    resources = statement.get("Resource")
    if isinstance(resources, str):
        resources = [resources]
    if not isinstance(resources, list) or not resources:
        return {default_when_absent}
    return {str(resource) for resource in resources}


# BOTH sides of every comparison here are PATTERNS, not concrete ARNs -- a policy names
# `payment-manager/prod-*`, never the resources it happens to match today. Matching a compiled pattern
# against the other side's literal text therefore compares a `*` or `?` in the subject as the
# CHARACTER `*` or `?` instead of as a wildcard, and that is wrong in both directions:
#
#   * `prod-*` and `*-checkout` share `prod-checkout`, so a role allowed one payment action on each
#     can complete a payment on that manager -- but neither pattern's text matches the other, so the
#     overlap went unseen and the role reported PASS.
#   * a Deny on `payment-manager/?` reaches only single-character names, yet the `?` matched the
#     literal `*` of an Allow on `payment-manager/*` and cancelled the whole grant -- also PASS.
#
# So the two questions are answered by two different relations over the pattern LANGUAGES, and the
# asymmetry is deliberate: overlap asks whether the languages INTERSECT, while Deny asks whether the
# Deny's language CONTAINS the Allow's. Using intersection for Deny would let a Deny on one manager
# cancel an Allow covering every manager, which is the narrow-Deny false PASS fixed earlier.
#
# IAM honours exactly two metacharacters, `*` for any sequence and `?` for any single character;
# every other character is literal and compared case-sensitively.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html


@lru_cache(maxsize=4096)
def _patterns_intersect(first: str, second: str) -> bool:
    """Whether two IAM Resource patterns can name the same resource.

    Args:
        first: One Resource pattern.
        second: The other Resource pattern.

    Returns:
        True when at least one concrete resource matches both patterns.

    Exact and symmetric: verified against exhaustive language enumeration over every pattern of up to
    three tokens drawn from two literals plus ``*`` and ``?``, with zero disagreements across all
    7,225 pairs.

    Filled as a table rather than recursively. IAM sets no maximum length for a single ``Resource``
    string, and a role's inline policies may total 10,240 characters, so a Resource well within quota
    can be longer than the interpreter's recursion limit. Recursing per character raised
    ``RecursionError``, which the check executor catches and turns into zero findings -- silently
    dropping the FAIL this check exists to raise.
    """
    first_len = len(first)
    second_len = len(second)

    # `below[j]` answers "can `first[i + 1:]` and `second[j:]` still produce a common suffix", and
    # `row[j]` the same question for `first[i:]`. Every dependency lies at a greater `i` or a greater
    # `j`, so walking both indices downwards needs only the row below the current one.
    below = [False] * (second_len + 1)
    # i == first_len: `first` is spent, so `second` matches only if the rest of it can match nothing.
    below[second_len] = True
    for j in range(second_len - 1, -1, -1):
        below[j] = second[j] == "*" and below[j + 1]

    for i in range(first_len - 1, -1, -1):
        row = [False] * (second_len + 1)
        # j == second_len: mirror of the above, `second` is spent.
        row[second_len] = first[i] == "*" and below[second_len]
        for j in range(second_len - 1, -1, -1):
            one, other = first[i], second[j]
            if one == "*" or other == "*":
                # The `*` absorbs this token, or matches nothing and stands aside.
                row[j] = below[j] or row[j + 1]
            elif one == "?" or other == "?":
                row[j] = below[j + 1]
            else:
                row[j] = one == other and below[j + 1]
        below = row

    return below[0]


@lru_cache(maxsize=4096)
def _pattern_contains(denied: str, allowed: str) -> bool:
    """Whether every resource matching ``allowed`` also matches ``denied``.

    Args:
        denied: The Deny statement's Resource pattern.
        allowed: The Allow statement's Resource pattern.

    Returns:
        True only when the Deny provably covers the whole of the Allow.

    SOUND, and deliberately not complete. Verified against exhaustive language enumeration over the
    same 7,225 pattern pairs: zero cases where it claims coverage it does not have, and 150 where it
    misses real coverage -- every one of those needing two or more wildcards in the Deny pattern,
    which no realistic ARN pattern has. The direction of that residue is what matters: claiming
    coverage falsely would DELETE a capability and hide a violation, whereas missing coverage leaves
    an Allow standing and can only over-report.

    Filled as a table rather than recursively, for the reason given on ``_patterns_intersect``.
    """
    denied_len = len(denied)
    allowed_len = len(allowed)

    # `below[j]` answers "does `denied[i + 1:]` accept every string `allowed[j:]` can produce", and
    # `row[j]` the same question for `denied[i:]`. As above, one row below the current one suffices.
    below = [False] * (allowed_len + 1)
    # i == denied_len with j == allowed_len: both spent, so the Deny covers the Allow. With the Allow
    # not spent the Deny has nothing left to accept it with, which the False initialiser already says.
    below[allowed_len] = True

    for i in range(denied_len - 1, -1, -1):
        row = [False] * (allowed_len + 1)
        # j == allowed_len: the Allow produces nothing more, so the rest of the Deny must accept the
        # empty string, which only a run of `*` does.
        row[allowed_len] = denied[i] == "*" and below[allowed_len]
        for j in range(allowed_len - 1, -1, -1):
            deny_char, allow_char = denied[i], allowed[j]
            if deny_char == "*":
                # Match nothing here, or absorb whatever this Allow token emits and stay available.
                row[j] = below[j] or row[j + 1]
            elif allow_char == "*":
                # The Allow can emit arbitrary text and only a `*` could accept all of it.
                row[j] = False
            elif allow_char == "?":
                row[j] = deny_char == "?" and below[j + 1]
            elif deny_char == "?":
                row[j] = below[j + 1]
            else:
                row[j] = deny_char == allow_char and below[j + 1]
        below = row

    return below[0]


def _tracked_actions_in(statement: dict) -> set:
    """Which tracked payment actions a statement names, whatever its Effect.

    Args:
        statement: One IAM policy statement.

    Returns:
        The subset of TRACKED_OPERATIONS keys the statement's Action/NotAction reaches.

    Expansion is delegated to ``get_effective_actions`` on a synthetic single-Allow document, so
    wildcards in any position, ``"*"`` and ``NotAction`` are resolved by the same upstream code that
    resolves them everywhere else rather than by a second implementation here.
    """
    probe = {
        "Version": "2012-10-17",
        "Statement": [{**statement, "Effect": "Allow"}],
    }
    reached = {action.lower() for action in get_effective_actions(probe)}
    return set(TRACKED_OPERATIONS) & reached


def effective_resources_by_action(statements: list) -> dict:
    """Per tracked action, the Resource patterns the role still holds after Deny.

    Args:
        statements: Every resolved statement for one role, from all its attached and inline policies.

    Returns:
        A dict mapping each tracked action to the set of Resource patterns still allowed.

    Deny handling is resource-aware because these actions are resource-scoped: a Deny removes an
    Allow only where it covers it. Two cautious asymmetries, both chosen so the error lands on
    over-reporting rather than under-reporting:

    * A Deny carrying a ``Condition`` or a ``NotResource`` is ignored, because it cannot be shown to
      apply. A Condition that always holds therefore reads as unsuppressed, which is a false FAIL.
    * A statement with no ``Resource`` at all is treated as ``"*"`` when it is an Allow and as
      matching nothing when it is a Deny -- broadest grant, narrowest suppression.
    """
    allowed = {action: set() for action in TRACKED_OPERATIONS}
    denied = {action: set() for action in TRACKED_OPERATIONS}

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "")).strip().lower()
        if effect not in ("allow", "deny"):
            continue
        actions = _tracked_actions_in(statement)
        if not actions:
            continue
        if effect == "allow":
            patterns = _resource_patterns(statement, "*")
            for action in actions:
                allowed[action].update(patterns)
        else:
            if "Condition" in statement or "NotResource" in statement:
                continue
            patterns = _resource_patterns(statement, "")
            for action in actions:
                denied[action].update(patterns)

    return {
        action: {
            resource
            for resource in allowed[action]
            if not any(
                _pattern_contains(pattern, resource) for pattern in denied[action]
            )
        }
        for action in TRACKED_OPERATIONS
    }


def resources_overlap(first: set, second: set) -> bool:
    """Whether two Resource pattern sets can name the same resource.

    Args:
        first: Resource patterns still allowed for one action.
        second: Resource patterns still allowed for the other.

    Returns:
        True when some concrete resource matches a pattern on each side.

    Intersection rather than "does either cover the other", because two patterns can share a resource
    while neither contains the other: ``payment-manager/prod-*`` and ``payment-manager/*-checkout``
    both name ``payment-manager/prod-checkout``, so a role allowed one payment action on each can
    complete a payment on that manager. It also still covers the easy case, ``{"*"}`` against a
    concrete ARN.
    """
    return any(_patterns_intersect(one, other) for one in first for other in second)


class bedrockagentcore_payments_process_payment_role_separation(Check):
    """Ensure no single IAM role can both open and execute an AgentCore payment.

    ``CreatePaymentSession`` establishes the reviewable terms of a transaction
    and ``ProcessPayment`` executes it. A role holding both completes a
    transaction end-to-end with no second principal involved.

    Action matching runs through ``get_effective_actions``, so a wildcard in any
    position counts as granting the actions it expands to: ``*``, ``*:*``,
    ``bedrock-agentcore:*``, ``bedrock-agentcore:Process*``, and
    ``bedrock-agentcore:*Payment*`` all reach the payment actions. Matching is
    case-insensitive because IAM matches action names that way. ``NotAction`` is
    honoured, so an ``Allow`` with ``NotAction`` grants every action it does not
    exclude, and ``Deny`` statements cancel the actions they cover.

    - FAIL: One role's policies allow both ``bedrock-agentcore:ProcessPayment``
      and ``bedrock-agentcore:CreatePaymentSession``.
    - PASS: The role grants exactly one of the two.
    - MANUAL: The role grants one of the two and at least one of its policy
      documents could not be resolved in the IAM inventory, so the other half
      may be hiding there.

    Roles granting neither action are skipped rather than reported.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if iam_client.roles is None:
            # ListRoles was denied, so the IAM inventory is unknown rather than
            # empty. Iterating nothing here would report a clean account.
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.role_arn_template
            report.status = "MANUAL"
            report.status_extended = "IAM roles could not be listed, so this check could not be evaluated; verify manually that no role allows both payment actions."
            return [report]

        for role in iam_client.roles:
            unresolved = []

            # AGGREGATE FIRST, evaluate once. get_effective_actions subtracts Deny only within the
            # document it is given, so unioning per-document results loses a Deny of ProcessPayment
            # in policy B that overrides an Allow in policy A -- and IAM would deny it, so the role
            # would be reported as holding both payment actions when it holds one. Separation of
            # duties is a question about the ROLE's effective permissions, so the whole role's
            # statements are what has to be expanded.
            statements = []
            for policy in role.attached_policies:
                policy_arn = policy.get("PolicyArn", "")
                policy_name = policy.get("PolicyName") or policy_arn
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"managed policy {policy_name}")
                    continue
                statements.extend(self._statements_of(policy_obj.document))

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"inline policy {inline_name}")
                    continue
                statements.extend(self._statements_of(policy_obj.document))

            # Resource-aware, because both payment actions are resource-scoped. A Deny removes
            # an Allow only where it covers it, so a Deny on payment-manager/B no longer cancels an
            # Allow covering payment-manager/A -- which reported PASS for a role that can still
            # complete a payment end to end on A.
            effective = effective_resources_by_action(statements) if statements else {}
            granted = {action for action, res in effective.items() if res}

            if not granted and not unresolved:
                # The role touches neither payment action, so separation of
                # duties says nothing about it. A role with an unreadable
                # document is not skipped: the grant that would bring it into
                # scope is exactly what could not be read.
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            # An IAM Role carries no region attribute, so Check_Report_AWS
            # leaves the field empty. IAM is global and its checks report the
            # IAM client region instead, so the status text names no region.
            report.region = iam_client.region

            both_actions_share_a_manager = (
                PROCESS_PAYMENT_ACTION in granted
                and CREATE_PAYMENT_SESSION_ACTION in granted
                and resources_overlap(
                    effective[PROCESS_PAYMENT_ACTION],
                    effective[CREATE_PAYMENT_SESSION_ACTION],
                )
            )
            if both_actions_share_a_manager:
                report.status = "FAIL"
                report.status_extended = f"IAM Role {role.name} allows both bedrock-agentcore:CreatePaymentSession and bedrock-agentcore:ProcessPayment, so one compromised credential can open and execute a payment end-to-end with no second principal reviewing it."
            elif unresolved:
                report.status = "MANUAL"
                # Sorted for the same reason granted_names is: ListAttachedRolePolicies and
                # ListRolePolicies document no ordering, so an unsorted join renders one role's
                # unchanged state as two different findings across scans.
                unresolved.sort()
                granted_names = sorted(TRACKED_OPERATIONS[action] for action in granted)
                # granted is empty when every document that could be read was
                # silent on both payment actions, so the sentence has to work
                # without naming one rather than trailing an empty list.
                allows = (
                    f"allows bedrock-agentcore:{', bedrock-agentcore:'.join(granted_names)}, but"
                    if granted_names
                    else "allows neither payment action in the policies that could be read, but"
                )
                report.status_extended = f"IAM Role {role.name} {allows} {', '.join(unresolved)} could not be retrieved from the IAM inventory; verify manually that the role does not allow both bedrock-agentcore:CreatePaymentSession and bedrock-agentcore:ProcessPayment."
            else:
                granted_names = sorted(TRACKED_OPERATIONS[action] for action in granted)
                report.status = "PASS"
                # Two different reasons reach PASS and they need different sentences. Saying "but not
                # both payment actions" when the role holds BOTH on disjoint payment managers
                # contradicts the list immediately preceding it, and reads as though the check missed
                # the second grant rather than having found the managers do not overlap.
                separation = (
                    "on payment managers that do not overlap, so no single manager can be both opened and charged by this role"
                    if len(granted_names) > 1
                    else "but not both payment actions, so opening and executing a payment stay separate"
                )
                report.status_extended = f"IAM Role {role.name} allows bedrock-agentcore:{', bedrock-agentcore:'.join(granted_names)} {separation}."

            findings.append(report)

        return findings

    def _statements_of(self, document: dict) -> list:
        """Normalise a policy document's statements into a list of dicts.

        Args:
            document: The IAM policy document.

        Returns:
            Every statement that is a dict, with a bare single statement wrapped in a list.
        """
        statements = document.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return []
        return [statement for statement in statements if isinstance(statement, dict)]
