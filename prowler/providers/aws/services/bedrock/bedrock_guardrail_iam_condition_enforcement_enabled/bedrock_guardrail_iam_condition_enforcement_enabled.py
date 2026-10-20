from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import iam_pattern_matches

BEDROCK_SERVICE_PREFIX = "bedrock"
GUARDRAIL_CONDITION_KEY = "bedrock:guardrailidentifier"
# The only two actions that accept the bedrock:GuardrailIdentifier condition key, per the AWS
# service authorization reference (servicereference.us-east-1.amazonaws.com/v1/bedrock/bedrock.json).
# The Converse and ConverseStream APIs are authorized through these same two actions.
GUARDRAIL_ENFORCEABLE_OPERATIONS = (
    "InvokeModel",
    "InvokeModelWithResponseStream",
)
# Condition operators that evaluate to false when the request carries no guardrail at all, so an
# Allow constrained by one of them cannot be used to invoke a model without a guardrail. Negated
# operators and every ...IfExists variant evaluate to true when the key is absent, and
# ForAllValues: is vacuously true on an absent key, so none of those enforce anything on an Allow.
ENFORCING_ALLOW_OPERATORS = (
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
    "arnequals",
    "arnlike",
    "foranyvalue:stringequals",
    "foranyvalue:stringequalsignorecase",
    "foranyvalue:stringlike",
    "foranyvalue:arnequals",
    "foranyvalue:arnlike",
)
# Condition operators that evaluate to true when the request carries no guardrail, so a Deny
# constrained by one of them refuses every guardrail-less invocation. This is the "deny unless a
# guardrail is applied" pattern, and it enforces the guardrail as surely as a constrained Allow.
GUARDRAIL_ABSENT_DENY_OPERATORS = (
    "stringnotequals",
    "stringnotequalsignorecase",
    "stringnotlike",
    "arnnotequals",
    "arnnotlike",
)


def _as_list(value) -> list:
    """Normalize to list: None -> [], scalar -> [value], list -> list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document: dict) -> list:
    """Return the policy statements, normalizing a single-statement dict to a list."""
    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _effect(statement: dict) -> str:
    """Return the statement effect lower-cased, or an empty string when it is malformed."""
    effect = statement.get("Effect", "")
    return effect.strip().lower() if isinstance(effect, str) else ""


def _operations_named(action_patterns: list) -> set:
    """Return the guardrail-enforceable operations that the given action patterns name.

    Each pattern is split into service and operation and both halves are matched as IAM patterns,
    so ``bedrock:Invoke*`` and ``bed*:InvokeModel`` are read as naming the operation.
    """
    named = set()
    for action in action_patterns:
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(":")
        if separator != ":":
            if service == "*":
                named.update(GUARDRAIL_ENFORCEABLE_OPERATIONS)
            continue
        if not iam_pattern_matches(service, BEDROCK_SERVICE_PREFIX):
            continue
        named.update(
            enforceable
            for enforceable in GUARDRAIL_ENFORCEABLE_OPERATIONS
            if iam_pattern_matches(operation, enforceable)
        )
    return named


def _granted_operations(statement: dict) -> set:
    """Return the guardrail-enforceable operations an Allow statement grants.

    An ``Action`` of ``*`` or ``*:*`` grants both operations like any other matching pattern. The
    administrative-privileges checks only look at statements on ``Resource: "*"``, so skipping it
    here would let ``Action: "*"`` on a Bedrock ARN pass both. ``NotAction`` is resolved exactly,
    because it grants every action it does not list: the operation is granted when no listed
    pattern names it.
    """
    if "NotAction" in statement:
        excluded = _operations_named(_as_list(statement.get("NotAction")))
        return set(GUARDRAIL_ENFORCEABLE_OPERATIONS) - excluded
    return _operations_named(_as_list(statement.get("Action")))


def _resource_reaches_bedrock(resource: str) -> bool:
    """Return True if a Resource entry could name a Bedrock resource.

    Decided field by field from the ARN shape rather than by matching example ARNs, so no region,
    account or resource name is load-bearing. A pattern with fewer than six fields reaches Bedrock
    only when a ``*`` in its last spelled-out field can span the fields it omits.
    """
    resource = resource.strip()
    if resource == "*":
        return True
    fields = resource.split(":", 5)
    if not iam_pattern_matches(fields[0], "arn"):
        return False
    if len(fields) < 6 and "*" not in fields[-1]:
        return False
    if len(fields) < 3:
        return True
    return iam_pattern_matches(fields[2], BEDROCK_SERVICE_PREFIX)


def _reaches_bedrock(statement: dict) -> bool:
    """Return True if the statement's resources could include a Bedrock model resource.

    ``NotResource`` grants everything outside its list, so it is treated as reaching Bedrock.
    """
    if "NotResource" in statement:
        return True
    return any(
        isinstance(resource, str) and _resource_reaches_bedrock(resource)
        for resource in _as_list(statement.get("Resource"))
    )


def _condition_keys_by_operator(statement: dict) -> dict:
    """Return the statement's Condition block as {lower-case operator: {lower-case keys}}."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return {}
    keys_by_operator = {}
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        keys_by_operator[operator.strip().lower()] = {
            key.strip().lower() for key in block if isinstance(key, str)
        }
    return keys_by_operator


def _null_values(statement: dict) -> list:
    """Return the values the statement's ``Null`` operator sets for the guardrail key."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return []
    for operator, block in condition.items():
        if not (isinstance(operator, str) and operator.strip().lower() == "null"):
            continue
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if isinstance(key, str) and key.strip().lower() == GUARDRAIL_CONDITION_KEY:
                return [str(item).strip().lower() for item in _as_list(value)]
    return []


def _allow_requires_guardrail(statement: dict) -> bool:
    """Return True if the Allow statement only applies when a guardrail is on the request.

    That holds when the guardrail key sits under an operator that is false for an absent key, or
    under ``Null`` set to ``false`` (the key must be present). Other keys in the same Condition
    block only narrow the grant further, so they do not change the answer.
    """
    for operator, keys in _condition_keys_by_operator(statement).items():
        if operator in ENFORCING_ALLOW_OPERATORS and GUARDRAIL_CONDITION_KEY in keys:
            return True
    return _null_values(statement) == ["false"]


def _deny_blocks_missing_guardrail(statement: dict) -> bool:
    """Return True if a Deny statement refuses every request that carries no guardrail.

    The Deny must be conditioned ONLY on the guardrail key, either through ``Null`` set to ``true``
    or a negated operator. A Deny that also tests another key applies only when that key matches
    too, so it does not take the guardrail-less path away in general.
    """
    keys_by_operator = _condition_keys_by_operator(statement)
    if not keys_by_operator:
        return False
    if any(keys != {GUARDRAIL_CONDITION_KEY} for keys in keys_by_operator.values()):
        return False
    if len(keys_by_operator) != 1:
        return False
    operator = next(iter(keys_by_operator))
    if operator == "null":
        return _null_values(statement) == ["true"]
    return operator in GUARDRAIL_ABSENT_DENY_OPERATORS


def _resource_covers(deny_resource: str, allow_resource: str) -> bool:
    """Return True if a Deny resource pattern covers every resource an Allow entry names.

    Wildcards in the Allow entry are not compared against the Deny pattern character by character,
    because a ``?`` in the Deny would then appear to cover a ``*`` in the Allow. Only three shapes
    are accepted: a Deny of ``*``, the identical pattern, or a Deny pattern matching a concrete Allow
    ARN that carries no wildcard.
    """
    deny_resource = deny_resource.strip()
    allow_resource = allow_resource.strip()
    if deny_resource in ("*", allow_resource):
        return True
    if "*" in allow_resource or "?" in allow_resource:
        return False
    return iam_pattern_matches(deny_resource, allow_resource)


def _deny_covers_statement(deny_resources: list, statement: dict) -> bool:
    """Return True if the Deny resources cover every Bedrock resource the Allow statement names."""
    deny_resources = [
        resource for resource in deny_resources if isinstance(resource, str)
    ]
    if "NotResource" in statement:
        return any(resource.strip() == "*" for resource in deny_resources)
    allow_resources = [
        resource
        for resource in _as_list(statement.get("Resource"))
        if isinstance(resource, str) and _resource_reaches_bedrock(resource)
    ]
    return all(
        any(_resource_covers(deny, allow) for deny in deny_resources)
        for allow in allow_resources
    )


def _operations_denied(statement: dict) -> set:
    """Return the enforceable operations a Deny statement names through ``Action``.

    ``NotAction`` on a Deny is not credited: it is not needed to express this control, and not
    crediting it errs toward reporting rather than toward silence.
    """
    if "NotAction" in statement:
        return set()
    return _operations_named(_as_list(statement.get("Action")))


def evaluate_guardrail_enforcement(document: dict) -> tuple:
    """Evaluate a policy document for Bedrock invocation grants that skip the guardrail key.

    An Allow is enforced when its own Condition requires the guardrail key. An Allow without that
    condition is still enforced for an operation when a Deny in the same policy covers all of its
    resources and either applies unconditionally or applies exactly when the guardrail is missing
    (``Null`` set to ``true``, or a negated operator on the guardrail key alone). That second shape
    is the one the Amazon Bedrock user guide uses in its own examples.

    Args:
        document: The IAM policy document.

    Returns:
        A tuple ``(granted, unenforced)`` of sets of operation names. ``granted`` holds every
        guardrail-enforceable operation the policy allows on a Bedrock resource; ``unenforced``
        holds those that can be invoked without the ``bedrock:GuardrailIdentifier`` key.
    """
    denies = []
    for statement in _statements(document):
        if _effect(statement) != "deny" or "NotResource" in statement:
            continue
        if statement.get("Condition") and not _deny_blocks_missing_guardrail(statement):
            continue
        operations = _operations_denied(statement)
        if operations:
            denies.append((operations, _as_list(statement.get("Resource"))))

    granted = set()
    unenforced = set()
    for statement in _statements(document):
        if _effect(statement) != "allow" or not _reaches_bedrock(statement):
            continue
        operations = _granted_operations(statement)
        granted.update(operations)
        if _allow_requires_guardrail(statement):
            continue
        covered = set()
        for denied_operations, deny_resources in denies:
            if _deny_covers_statement(deny_resources, statement):
                covered.update(denied_operations)
        unenforced.update(operations - covered)
    return granted, unenforced


class bedrock_guardrail_iam_condition_enforcement_enabled(Check):
    """Ensure IAM policies that allow Bedrock model invocation require a guardrail.

    Evaluates customer-managed and inline IAM policies that allow ``bedrock:InvokeModel`` or
    ``bedrock:InvokeModelWithResponseStream`` on Bedrock resources.

    - PASS: every such Allow is constrained by the ``bedrock:GuardrailIdentifier`` condition key,
      or the guardrail-less path is removed by a Deny in the same policy.
    - FAIL: an Allow lets the holder invoke a model without naming a guardrail.
    - MANUAL: the policy document could not be retrieved.

    Policies that grant neither operation produce no finding. AWS-managed policies are skipped
    because they cannot be edited to remediate a finding.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for policy in iam_client.policies.values():
            if policy.type not in ("Custom", "Inline"):
                continue
            if (
                policy.type == "Custom"
                and not policy.attached
                and not iam_client.provider.scan_unused_services
            ):
                continue

            if policy.type == "Inline":
                label = f"Inline policy {policy.name} of {policy.entity}"
            else:
                label = f"Custom policy {policy.name}"

            if not policy.document:
                report = self._report(policy)
                report.status = "MANUAL"
                report.status_extended = (
                    f"{label} could not be evaluated because its policy document "
                    "was not retrieved."
                )
                findings.append(report)
                continue

            granted, unenforced = evaluate_guardrail_enforcement(policy.document)
            if not granted:
                continue

            report = self._report(policy)
            if unenforced:
                actions = ", ".join(
                    f"{BEDROCK_SERVICE_PREFIX}:{operation}"
                    for operation in sorted(unenforced)
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"{label} allows {actions} without requiring the "
                    "bedrock:GuardrailIdentifier condition key, so models can be invoked "
                    "without a guardrail."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"{label} allows Bedrock model invocation only when the "
                    "bedrock:GuardrailIdentifier condition key is satisfied."
                )
            findings.append(report)
        return findings

    def _report(self, policy) -> Check_Report_AWS:
        """Build a report for the policy, keyed like the other inline-policy checks."""
        report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
        report.region = iam_client.region
        if policy.type == "Inline":
            report.resource_id = f"{policy.entity}/{policy.name}"
        return report
