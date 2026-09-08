import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.oam.oam_client import oam_client
from prowler.providers.aws.services.oam.oam_service import SinkPolicyState

# Condition keys that bind a sink policy's principal to an AWS Organization.
ORGANIZATION_CONDITION_KEYS = {"aws:principalorgid", "aws:principalorgpaths"}

# Only these operators positively constrain the key. StringNotEquals inverts the match and the
# *IfExists variants pass when the key is absent, which is the case for a principal outside any
# organization, so neither of those scopes an Allow statement.
ORGANIZATION_CONDITION_OPERATORS = {
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
}

# The two IAM metacharacters, honoured by StringLike in a condition value and by IAM in an
# Action pattern. Either one stands for text the policy author did not write, so a pattern
# reaches actions its author never named.
WILDCARD = re.compile(r"[*?]")

# The sink-scoped OAM actions that cannot establish or widen a link. Every one is Read access
# level in the service authorization reference, so a statement confined to them exposes the
# sink's own metadata and nothing else. Deliberately absent are the Write actions the same
# reference scopes to a sink: oam:CreateLink and oam:UpdateLink are the pair AWS's own sink
# policy examples grant to permit linking, and oam:PutSinkPolicy replaces the policy outright,
# which lets a principal grant itself the first two.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_oam.html
# https://docs.aws.amazon.com/OAM/latest/APIReference/API_PutSinkPolicy.html
INERT_SINK_ACTIONS = {
    "oam:getsink",
    "oam:getsinkpolicy",
    "oam:listattachedlinks",
    "oam:listtagsforresource",
}

# aws:PrincipalOrgID is an organization ID and an aws:PrincipalOrgPaths entry begins with one, so
# a value only names ONE organization once a whole organization ID is literal text. AWS documents
# that ID as "o-" followed by 10 to 32 lowercase letters or digits, and documents a path as that
# same ID followed by "/" and the entity path below it. The terminator is what makes the match
# sound rather than the length on its own: "o-a1b2c3d4e5" and "o-a1b2c3d4e5/*" each name one
# organization, while "o-a*" and "o-a1b2c3d4e5*" leave the ID unfinished -- because IDs run to 32
# characters, the second still matches every longer ID beginning those 10 -- and "*" and "o-*"
# name every organization there is.
# https://docs.aws.amazon.com/organizations/latest/APIReference/API_Organization.html
# https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html
COMPLETE_ORGANIZATION_ID = re.compile(r"o-[a-z0-9]{10,32}($|/)")


def _grants_to_any_principal(statement: dict) -> bool:
    """Whether the statement's principal is anything other than an enumerated set of accounts."""
    if "NotPrincipal" in statement:
        # An Allow with NotPrincipal grants every principal except the ones listed.
        return True
    principal = statement.get("Principal")
    if isinstance(principal, str):
        return principal == "*"
    if isinstance(principal, dict):
        for value in principal.values():
            values = value if isinstance(value, list) else [value]
            if "*" in values:
                return True
    return False


def _names_an_organization(value) -> bool:
    """Whether a condition value identifies one organization rather than any organization.

    The whole organization ID has to be literal. A wildcard reaching into the ID, or sitting
    where the ID's next character would be, leaves the ID unfinished, and both IAM
    metacharacters then stand for text the policy author never wrote, so the value can select
    organizations besides the intended one. Matching the entire value is what enforces that:
    neither metacharacter is in [a-z0-9], so a wildcard within the ID cannot be matched over,
    and one immediately after it fails the terminator that has to be either "/" or the end of
    the value.

    Args:
        value: A single aws:PrincipalOrgID or aws:PrincipalOrgPaths value from the policy.
    """
    return bool(COMPLETE_ORGANIZATION_ID.match(str(value).strip().lower()))


def _requires_the_key(condition: dict, key: str) -> bool:
    """Whether the Condition also requires the given key to be present in the request.

    Args:
        condition: The Allow statement's Condition block.
        key: A lowercased condition key name.
    """
    for operator, keys in condition.items():
        if str(operator).split(":")[-1].lower() != "null":
            continue
        if not isinstance(keys, dict):
            continue
        for null_key, null_value in keys.items():
            if str(null_key).lower() != key:
                continue
            # Null: false demands that the key exist and be non-null; Null: true demands the
            # opposite, so only "false" turns an absent key into a non-match.
            values = null_value if isinstance(null_value, list) else [null_value]
            if values and all(str(item).strip().lower() == "false" for item in values):
                return True
    return False


def _scoped_to_organization(condition) -> bool:
    """Whether the Condition binds the principal to an organization or an organization path.

    Args:
        condition: The Allow statement's Condition block, or None when it has none.
    """
    if not isinstance(condition, dict):
        return False
    for operator, keys in condition.items():
        # ForAnyValue:/ForAllValues: qualify the operator, and aws:PrincipalOrgPaths is
        # multi-valued so it is documented with them.
        qualifier, _, base_operator = str(operator).rpartition(":")
        if base_operator.lower() not in ORGANIZATION_CONDITION_OPERATORS:
            continue
        if not isinstance(keys, dict):
            continue
        for key, value in keys.items():
            key = str(key).lower()
            if key not in ORGANIZATION_CONDITION_KEYS:
                continue
            # ForAllValues is true when the key is absent from the request, so on its own it
            # admits the very principal it looks like it excludes: one in no organization at
            # all. AWS documents pairing it with Null: false to require the key. ForAnyValue
            # is already false on an absent key and needs no guard.
            if qualifier.lower() == "forallvalues" and not _requires_the_key(
                condition, key
            ):
                continue
            values = value if isinstance(value, list) else [value]
            if values and all(_names_an_organization(item) for item in values):
                return True
    return False


def _can_authorize_a_link(statement: dict) -> bool:
    """Whether the statement's actions leave it able to establish or widen a link.

    A statement is ruled out only when every action it names is one that provably cannot
    link, because misreading one costs a genuinely open sink reported as compliant. An
    absent Action, a NotAction and any wildcard are all therefore read as able to link.

    Args:
        statement: An Allow statement from a sink resource policy.
    """
    if "NotAction" in statement:
        # NotAction names what the statement does not cover, so every action missing from
        # that list is granted: NotAction ["s3:*"] permits all of OAM, linking included.
        return True
    actions = statement.get("Action")
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, list) or not actions:
        # An Allow carrying no readable Action member is not a narrow grant. Ruling it out
        # would rest on a shape this cannot evaluate rather than on a permission it lacks.
        return True
    for action in actions:
        action = str(action).strip().lower()
        # Exact set membership is the mechanism here, never pattern matching, and that is
        # what keeps fnmatch out: fnmatch reads the [sS] of "oam:Get[sS]ink" as a character
        # class and would rule the statement out, while IAM honours only * and ? and so
        # reads those three characters literally, matching no action at all.
        #
        # The wildcard search is belt and braces rather than the working part. Membership
        # alone already rejects every pattern, because a pattern reaches actions its author
        # never typed and no INERT_SINK_ACTIONS member carries a metacharacter for it to
        # equal -- an invariant a test pins. The guard is here so that if a member ever did
        # carry one, a policy naming that pattern still could not buy an exclusion.
        if WILDCARD.search(action) or action not in INERT_SINK_ACTIONS:
            return True
    return False


def _allows_any_account_to_link(policy: dict) -> bool:
    """Whether the sink policy lets an account outside the organization link to the sink.

    Args:
        policy: A decoded sink resource policy.
    """
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not _grants_to_any_principal(statement):
            continue
        if not _can_authorize_a_link(statement):
            continue
        if not _scoped_to_organization(statement.get("Condition")):
            return True
    return False


class oam_sink_policy_restricted_to_organization(Check):
    """Flag Observability Access Manager sinks any AWS account can link to.

    A sink is the resource a monitoring account exposes to receive telemetry, and its
    resource policy is the only thing deciding who may link into it. A policy that allows
    oam:CreateLink to every principal without binding it to an organization lets an
    account outside the organization attach itself as a source, so the monitoring account
    ingests, stores and bills for observability data it never agreed to receive.
    Statements are read for all three parts of that grant: an unenumerated principal, an
    action that can establish or widen a link, and a Condition that genuinely constrains
    aws:PrincipalOrgID or aws:PrincipalOrgPaths to a named organization. A statement
    confined to read-only sink actions cannot link and so does not carry the finding.
    Sinks with no policy at all are reported as PASS because no
    account can link to them, and sinks whose policy could not be read are MANUAL rather
    than a proven outcome.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate which accounts each Observability Access Manager sink can be linked by.

        Returns:
            list[Check_Report_AWS]: One report per sink. FAIL when the resource policy
            allows an unenumerated principal to link without an organization condition;
            MANUAL when the policy could not be determined; PASS when no policy is
            attached or the policy restricts who may link.
        """
        findings = []
        for sink in oam_client.sinks.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=sink)
            if sink.policy_state == SinkPolicyState.UNKNOWN:
                report.status = "MANUAL"
                # Do not assert the policy EXISTS. UNKNOWN covers a denied GetSinkPolicy,
                # which says nothing about existence, and a successful response carrying
                # nothing usable. Claiming there "is" a policy overstates what was read.
                report.status_extended = f"Observability Access Manager sink {sink.name} resource policy could not be determined, so the accounts able to link to it are unknown; review it manually."
            elif sink.policy_state == SinkPolicyState.ABSENT:
                report.status = "PASS"
                report.status_extended = f"Observability Access Manager sink {sink.name} does not have a resource policy, so no account can link to it."
            elif _allows_any_account_to_link(sink.policy):
                report.status = "FAIL"
                report.status_extended = f"Observability Access Manager sink {sink.name} has a resource policy allowing any AWS account to link to it without restricting them to an organization."
            else:
                report.status = "PASS"
                report.status_extended = f"Observability Access Manager sink {sink.name} has a resource policy restricting which accounts can link to it."
            findings.append(report)

        return findings
