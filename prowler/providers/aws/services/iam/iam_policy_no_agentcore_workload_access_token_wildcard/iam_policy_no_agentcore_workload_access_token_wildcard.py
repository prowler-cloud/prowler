from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import iam_pattern_matches

AGENTCORE_SERVICE_PREFIX = "bedrock-agentcore"
# The three operations that hand a caller a workload access token. Confirmed against the
# bedrock-agentcore service model: GetWorkloadAccessToken issues a token for the calling
# workload, ForJWT exchanges a user JWT, ForUserId names the user directly.
WORKLOAD_ACCESS_TOKEN_OPERATIONS = (
    "GetWorkloadAccessToken",
    "GetWorkloadAccessTokenForJWT",
    "GetWorkloadAccessTokenForUserId",
)
# Every workload identity ARN sits under the workload-identity-directory resource path, both the
# directory itself and the workload-identity children beneath it.
WORKLOAD_IDENTITY_SEGMENT = "workload-identity-directory"
# The leading resource-path segment of every AgentCore type that is NOT a workload identity, from
# AWS's machine-readable service reference
# (servicereference.us-east-1.amazonaws.com/v1/bedrock-agentcore/bedrock-agentcore.json): 32 resource
# types collapsing to 23 distinct leading segments, of which workload-identity-directory is the only
# one hosting the two in-scope types.
#
# SEGMENTS, NOT NAMES, and that distinction is the whole point. This replaced four concrete probe
# resources -- token-vault/default, gateway/my-gateway, runtime/my-runtime and one workload identity
# called another-workload -- whose example NAMES were load-bearing. A resource field keyed on any
# other name matched none of them, so the check concluded it was confined to the workload-identity
# namespace and PASSed: "...:*prod-*" reaches runtime/prod-chatbot, gateway/prod-chatbot-gw,
# memory/prod-chatbot-mem and two distinct workload identities, and was reported as reaching none of
# them. Names cannot be enumerated -- the AgentCore devguide's own examples are prod-chatbot,
# dev-chatbot and customer-support-agent, and its own example policy wildcards on the name -- so no
# probe corpus can be completed. Resource TYPES can be enumerated, and are, above.
#
# This is the same correction already applied to the two short-ARN branches, which stopped pinning
# region, account and partition for exactly this reason; here it stops pinning the resource NAME.
NON_WORKLOAD_IDENTITY_SEGMENTS = (
    "ab-test",
    "batch-evaluate",
    "browser",
    "browser-custom",
    "browser-profile",
    "capacity-provider",
    "code-interpreter",
    "code-interpreter-custom",
    "configuration-bundle",
    "dataset",
    "evaluator",
    "gateway",
    "harness",
    "memory",
    "online-evaluation-config",
    "payment-manager",
    "policy-engine",
    "recommendation",
    "registry",
    "runtime",
    "token-vault",
    "tool",
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


def _covered_token_operations(statement: dict) -> set:
    """Return the workload access token operations this statement's Action covers.

    Only actions that can name the bedrock-agentcore service are read, and the service field is
    matched as an IAM pattern rather than compared literally -- `bedrock-*:GetWorkloadAccessToken`
    reaches the operation, and an exact comparison read it as granting nothing at all.

    A bare "*" is deliberately not treated as a grant of these operations: a statement allowing
    every action on every resource is what check_admin_access reports, and re-reporting it here
    would duplicate the administrative-privileges checks rather than add a claim. The
    `separator != ":"` guard is what preserves that, since "*" partitions to an empty separator.
    """
    covered = set()
    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(":")
        # A statement allowing EVERY action is the administrative-privileges checks' finding,
        # whether it is spelled "*" or "*:*"; re-reporting it here would duplicate them. The
        # separator test covers the bare "*", which partitions to an empty separator.
        if separator != ":" or (service == "*" and operation == "*"):
            continue
        if not iam_pattern_matches(service, AGENTCORE_SERVICE_PREFIX):
            continue
        covered.update(
            token_operation
            for token_operation in WORKLOAD_ACCESS_TOKEN_OPERATIONS
            if iam_pattern_matches(operation, token_operation)
        )
    return covered


def _token_operations_removed_by(statement: dict) -> set:
    """Return the token operations a DENY statement's Action removes.

    Separate from _covered_token_operations on purpose, because the bare-star exclusion that is
    right on the Allow side inverts on the Deny side. There, skipping ``*`` and ``*:*`` avoids
    duplicating the administrative-privileges checks; here it meant an unconditional Deny of EVERY
    action credited nothing, so a policy that grants nothing at all was reported FAIL at high
    severity -- contradicting this check's own published Notes, which say an unconditional Deny of
    the operation on Resource "*" clears the finding. The Allow-side guard is deliberately left
    alone: relaxing it would reverse the settled decision that admin-level grants belong to
    check_admin_access.

    Deny expressed as NotAction is still NOT read, here or on the Allow side. Inverting it requires
    resolving the whole action namespace, which is more than this check can claim; not crediting it
    errs toward reporting rather than toward silence, so a policy denied that way may still FAIL.
    """
    removed = set()
    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(":")
        if separator != ":":
            # A bare "*" denies every action, these three among them.
            if service == "*":
                removed.update(WORKLOAD_ACCESS_TOKEN_OPERATIONS)
            continue
        if not iam_pattern_matches(service, AGENTCORE_SERVICE_PREFIX):
            continue
        removed.update(
            token_operation
            for token_operation in WORKLOAD_ACCESS_TOKEN_OPERATIONS
            if iam_pattern_matches(operation, token_operation)
        )
    return removed


def _may_reach_segment(resource_field: str, segment: str) -> bool:
    """Return True if this resource field could name a resource whose path starts with ``segment``.

    Decided from the field's own shape rather than by matching example resources, so no resource NAME
    is load-bearing. The two wildcards are NOT interchangeable and that distinction is the whole
    function: ``*`` spans any run of characters including none, while ``?`` consumes EXACTLY ONE. So
    the field's HEAD -- everything before its first ``*`` -- is a fixed-length template in which each
    ``?`` stands for one unknown character, and every string the field matches begins with something
    that template accepts.

    Compare the template to the segment position by position, then decide who supplies the remainder:

    - A position where the template holds a literal that differs from the segment's character rules
      the segment out entirely, however long the field is.
    - If the template is at least as long as the segment and no position disagreed, the segment is
      covered, so the field may reach it.
    - If the template is SHORTER, only a ``*`` can supply what is missing. Without one the field has
      a fixed length too short to contain the segment, so it reaches nothing under it.

    THE HEAD IS CUT AT ``*`` ONLY, NEVER AT ``?``, and the two must not be treated alike. ``?``
    consumes exactly one character, so it belongs to the fixed-length head and is skipped
    position-by-position above; ``*`` spans an unbounded run, so it terminates the head. Cutting at
    ``?`` as well empties the head of any ``?``-leading field, an empty head is compatible with every
    segment, and the field then reads as reaching all 22 of them: ``?orkload-identity-directory/*``
    would be reported while its byte-neighbour ``w?rkload-identity-directory/*`` is not. Measured
    against an exact oracle over 1345 fields, that spelling costs 265 false FAILs.

    THE COMPLEMENTARY ERROR IS TO RETURN False ON AN EMPTY HEAD, and it is worse. That repairs the
    ``?`` rows and simultaneously turns bare ``*`` and ``*prod-*`` into "reaches nothing", which
    reinstates the false PASS this segment test exists to remove: 10 oracle mismatches against 0 for
    the rule as written. So the decision rests on whether a ``*`` is PRESENT, not on whether the head
    is empty, because ``*`` must keep absorbing everything.

    Deliberately errs toward True on a coarse pair such as head ``browser-custom/x`` against segment
    ``browser``: over-estimating reach can only move a verdict toward reporting, and the reach test
    that follows still decides the workload-identity question on its own terms.
    """
    head, spans = resource_field.split("*", 1)[0], "*" in resource_field
    for index in range(min(len(head), len(segment))):
        if head[index] != "?" and head[index] != segment[index]:
            return False
    if len(head) >= len(segment):
        return True
    return spans


def _reaches_other_workload_identities(resource: str) -> bool:
    """Return True if this resource lets the token actions name a workload identity that
    is not the caller's own.

    A resource confined to the workload-identity-directory namespace is accepted, wildcards
    within it included: the AgentCore console itself issues that scope, and the ARN type is
    the granularity this check asserts. A resource of some other AgentCore type -- a token
    vault, a gateway -- is accepted too, but for the opposite reason: the token actions
    accept no such resource, so the grant reaches no workload identity at all.

    EVERY field of the pattern is matched as an IAM pattern, the first one included, because a
    leading star matches "arn" as surely as it matches anything else. Comparing that field to the
    literal "arn" instead would read ``*:aws:bedrock-agentcore:us-east-1:123456789012:*`` and
    ``*:*:*:*:*:*`` as naming no workload identity, while their correctly spelled six-field
    equivalent names every one.

    A pattern with fewer than six fields reaches a workload identity when a star in its LAST
    spelled-out field can span the fields it never spells out, because IAM wildcards match the
    colon. That question is answered structurally rather than by probing a concrete ARN, and
    deliberately so: matching against one ``us-east-1``/``123456789012`` ARN made the region,
    account and partition load-bearing, so ``arn:aws:bedrock-agentcore:us-west-2:*`` was read as
    reaching nothing while the byte-identical ``us-east-1`` spelling FAILed. No finite probe corpus
    fixes that -- ``arn:aws:bedrock-agentcore:us-east-1:178113193057*`` is an account PREFIX and
    there is nothing to enumerate. What the fields it does spell out must still do is name an ARN
    at all: ``arn:aws:s3:*`` is short and starred but names another service.

    ``arn:aws:bedrock-agentcore`` and ``arn:aws:bedrock-agentcore:us-east-1`` carry no star, so they
    match no ARN and reach nothing. The star is what separates them from the cases above, not the
    length.

    THE RESOURCE FIELD IS DECIDED STRUCTURALLY TOO, by ``_may_reach_segment`` against the enumerable
    list of AgentCore resource-path segments, and NOT by comparison against concrete example
    resources. The tempting argument for a small probe corpus is that the namespace test intercepts
    everything confined to workload-identity-directory before this one runs, so a single probe cannot
    produce a false verdict. That premise does not hold:

    ``arn:aws:bedrock-agentcore:us-east-1:123456789012:*prod-*`` is not confined to the namespace, yet
    it matched none of the four probes, so the namespace test intercepted it anyway and the check
    PASSed a statement reaching ``runtime/prod-chatbot``, ``gateway/prod-chatbot-gw``,
    ``memory/prod-chatbot-mem``, a token vault, a custom browser, and two distinct workload
    identities. Driven, the pair that shows it has no defensible boundary: resource field ``*``
    FAILed while ``*prod-*`` PASSed, and nothing stated anywhere in this file separated them. The only
    rule that did was "matches one of four example NAMES", which is an implementation artifact.

    So the lesson is the one the short-ARN branches already record, one level down: a probe corpus can
    only decide a question whose answer space it enumerates. Regions, accounts and partitions could
    not be enumerated there; resource NAMES cannot be enumerated here, since AgentCore creates
    identities named after the runtime or gateway that made them. Resource TYPES can be, so the test
    is built on those.
    """
    resource = resource.strip()
    if resource == "*":
        return True
    arn_fields = resource.split(":", 5)
    if len(arn_fields) < 6:
        if "*" not in arn_fields[-1]:
            return False
        if not iam_pattern_matches(arn_fields[0], "arn"):
            return False
        return len(arn_fields) < 3 or iam_pattern_matches(
            arn_fields[2], AGENTCORE_SERVICE_PREFIX
        )
    if not iam_pattern_matches(arn_fields[0], "arn"):
        return False
    if not iam_pattern_matches(arn_fields[2], AGENTCORE_SERVICE_PREFIX):
        return False
    resource_field = arn_fields[5]
    # Confined to the workload-identity namespace when it can reach NO resource of another AgentCore
    # type. The startswith test this replaced asked whether the field begins with the literal
    # namespace prefix, which is a different question and got the ordering backwards: the confined
    # workload-identity-* was reported while the strictly broader workload-identity-directory* --
    # whose reach is a superset of it -- was accepted.
    #
    # BOTH TESTS ARE STRUCTURAL, and they have to stay that way together. Comparing a field against
    # concrete example resources instead lets a field keyed on any name those examples do not use
    # satisfy both at once: "*prod-*" matches none of the four non-workload-identity probes, so this
    # branch would call it confined, and it also misses the single another-workload probe below, so
    # neither test would report it. Making only one of them structural leaves the verdict unchanged,
    # so do not read this branch as a guard for the one below -- it does not intercept everything
    # confined to the namespace, and a pattern that is not confined at all can reach it.
    if not any(
        _may_reach_segment(resource_field, segment)
        for segment in NON_WORKLOAD_IDENTITY_SEGMENTS
    ):
        return False
    return _may_reach_segment(resource_field, WORKLOAD_IDENTITY_SEGMENT)


def _is_workload_identity_scoped(statement: dict) -> bool:
    """Return True if no resource the statement names reaches another workload identity.

    A statement using NotResource names no resource at all -- it grants everything except
    an excluded list -- so it is not scoped.

    Only Resource and NotResource are read. An Allow-side Condition is NOT evaluated, so a
    statement narrowed solely by one -- aws:ResourceTag is a condition key on both workload
    identity resource types -- is still reported. That is deliberate conservatism, the mirror
    of the Deny-side decision below: a condition is not credited with confining a grant any
    more than it is credited with removing one. What it costs is that the finding may name a
    statement an unread condition already scopes, which is why the FAIL text claims only that
    the RESOURCES do not confine it.
    """
    resources = _as_list(statement.get("Resource"))
    if not resources:
        return "NotResource" not in statement
    return not any(
        isinstance(resource, str) and _reaches_other_workload_identities(resource)
        for resource in resources
    )


def _denied_token_operations(document: dict) -> set:
    """Return the token operations an unconditional Deny removes across all resources.

    A conditional Deny is not counted: it only applies when the condition holds, so it
    does not take the permission away from the request the Allow statement grants.
    """
    denied = set()
    for statement in _statements(document):
        if statement.get("Effect") != "Deny" or statement.get("Condition"):
            continue
        if any(
            isinstance(resource, str) and resource.strip() == "*"
            for resource in _as_list(statement.get("Resource"))
        ):
            denied.update(_token_operations_removed_by(statement))
    return denied


def _has_unevaluated_notaction(document: dict) -> bool:
    """True if an Allow statement expresses its actions as NotAction.

    NotAction under Effect Allow grants everything EXCEPT what it lists, so a policy using
    it can grant the very actions this check looks for while carrying no Action key at all.
    Reading only Action would find nothing and report a clean policy. Inverting NotAction
    correctly means resolving it against the full action namespace and its interaction with
    Resource and NotResource, which is more than this check can honestly claim to do -- so
    the statement is declared unevaluated rather than guessed at.
    """
    for statement in _statements(document):
        if statement.get("Effect") == "Allow" and "NotAction" in statement:
            return True
    return False


class iam_policy_no_agentcore_workload_access_token_wildcard(Check):
    """Check whether a customer-managed policy scopes AgentCore workload access token retrieval.

    A workload access token identifies the agent to AgentCore, so a policy granting the retrieval
    operations on every resource lets its holder obtain a token for any workload identity and act as
    that agent. FAIL when the grant reaches workload identities beyond a named directory; PASS when
    the resource is confined to the workload-identity-directory namespace, when it names an AgentCore
    type these actions do not accept, or when an unconditional Deny on ``Resource: "*"`` clears it;
    MANUAL when the policy document could not be read or expresses a shape this check does not
    evaluate.

    Caveats:
        Customer-managed policies only. The assertion is at ARN-type granularity rather than per
        workload identity, because a wildcard inside the directory namespace is the scope the
        AgentCore console itself issues. A bare ``Action: "*"`` is left to the
        administrative-privileges checks.
    """

    def execute(self) -> Check_Report_AWS:
        """Flag policies granting token ops beyond caller's workload ID.

        MANUAL is used deliberately below, where the document could not be read or expresses a shape
        this check does not evaluate. An unread document must not report as compliant: the grant it
        might contain is precisely what is being looked for, so PASS there would assert something never
        established. This is not off-contract -- 110 upstream checks emit MANUAL and
        `lib/check/models.py` places no restriction on it.

        THE COST, recorded so it is not rediscovered: `lib/outputs/asff/asff.py` SKIPS findings whose
        status is MANUAL, because MANUAL is not a valid Security Hub compliance state. A Security Hub
        consumer therefore sees NOTHING for an unreadable policy, and absence there reads as
        compliance. CSV and OCSF keep the status, so the information survives in those outputs. That is
        a gap in one output format, not a reason to report an unread document as PASS or FAIL.
        """
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
                    "NotAction, which this check does not evaluate, so its effective grants "
                    "could not be determined; review it manually."
                )
                findings.append(report)
                continue

            denied = _denied_token_operations(policy.document)
            unscoped = set()
            for statement in _statements(policy.document):
                if statement.get("Effect") != "Allow":
                    continue
                if _is_workload_identity_scoped(statement):
                    continue
                unscoped.update(_covered_token_operations(statement) - denied)

            if unscoped:
                report.status = "FAIL"
                report.status_extended = (
                    f"Custom Policy {policy.name} allows "
                    f"{', '.join(sorted(AGENTCORE_SERVICE_PREFIX + ':' + operation for operation in unscoped))} "
                    "on resources outside a workload identity ARN, so its resources do not "
                    "confine token retrieval to the workload's own identity; conditions on "
                    "the statement are not evaluated."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Custom Policy {policy.name} does not allow AgentCore workload access "
                    "token retrieval outside a workload identity ARN."
                )
            findings.append(report)

        return findings
