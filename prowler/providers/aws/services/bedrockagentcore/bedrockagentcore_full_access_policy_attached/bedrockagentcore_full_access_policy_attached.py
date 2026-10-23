from functools import lru_cache

from py_iam_expand.actions import InvalidActionHandling, expand_actions

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_full_service_access

# AWS-managed policy names that grant the whole AgentCore surface.
# AWS did NOT rename BedrockAgentCoreFullAccess. Both managed policies exist and are attachable:
# BedrockAgentCoreFullAccess is at v19, updated 2026-08-11 -- five days AFTER the new policy shipped --
# and still grants bedrock-agentcore:*, while AgentRegistryFullAccess (v1, 2026-08-06) grants
# agent-registry:* plus six narrow resource-scoped bedrock-agentcore actions and NOT bedrock-agentcore:*.
# AWS moved the Agent Registry surface into its own IAM namespace and states in bold that the old policy
# will NOT be updated to carry agent-registry:* (bedrock-agentcore devguide, registry-faq). Both names
# are matched because each grants service-wide administrative access to an AgentCore surface -- not
# because one replaced the other.
#
# The AgentCore namespaces. The registry migration moved the registry actions
# from bedrock-agentcore to agent-registry, so a policy may grant either.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-faq.html
AGENTCORE_NAMESPACE = "bedrock-agentcore"
AGENT_REGISTRY_NAMESPACE = "agent-registry"
AGENTCORE_NAMESPACES = (AGENTCORE_NAMESPACE, AGENT_REGISTRY_NAMESPACE)
# Which namespace each AWS-managed policy actually grants in full. Needed because the grant has to
# take part in the ROLE-level Deny evaluation rather than being reported on sight: a role carrying
# BedrockAgentCoreFullAccess alongside an inline Deny of bedrock-agentcore:* cannot call the service,
# and IAM says so. Matching the policy by name establishes the Allow; only the aggregate says whether
# it survives.
FULL_ACCESS_POLICY_NAMESPACE = {
    "BedrockAgentCoreFullAccess": AGENTCORE_NAMESPACE,
    "AgentRegistryFullAccess": AGENT_REGISTRY_NAMESPACE,
}

# Matching on the policy NAME is load-bearing, not a convenience. check_full_service_access requires the
# Allow statement's Resource list to contain the literal "*", and both real AWS-managed documents scope
# to arn:aws:<namespace>:*:*:* -- measured, the helper returns False for each. So this suffix list is the
# only thing that catches either AWS-managed policy; dropping a name flips a role holding it to PASS.
#
# DERIVED from FULL_ACCESS_POLICY_NAMESPACE rather than restated, because the two must hold the same
# names and the failure mode of drift is silent: a name present here but absent from the map yields no
# namespace, so the caller stops treating the policy as a full-access grant and the role flips to PASS.
# One literal list means a new managed policy cannot be added to the recogniser without also declaring
# which namespace it grants.
FULL_ACCESS_POLICY_SUFFIXES = frozenset(FULL_ACCESS_POLICY_NAMESPACE)

# The agent-registry actions, lowercased. Read from the service-authorization reference
# (list_agent-registry.html), taking BOTH its tables: "Actions defined by AWS Agent Registry" and
# "Permission-only actions", which are not invocable through any API but are equally usable in an
# IAM policy -- so a grant of the whole namespace includes them. Omitting the permission-only
# DeleteResourcePolicy / GetResourcePolicy / PutResourcePolicy would matter most of all here,
# because PutResourcePolicy is how cross-account access to a registry is granted.
#
# An INCOMPLETE list makes this check report FAIL for a policy that grants only the listed subset:
# the enumerated set is what "every action in the namespace" is measured against, so anything left
# out shrinks the target and a partial grant clears it.
# check_full_service_access expands a
# namespace against the action list backing py_iam_expand, which does not yet
# carry this namespace; expanding an unknown namespace yields an empty target
# set, which its issubset() test then reports as full access for every policy.
# Enumerating the namespace keeps the same "does the grant reach every action"
# question answerable without that false positive.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-iam-permissions.html
AGENT_REGISTRY_ACTIONS = frozenset(
    action.lower()
    for action in (
        "CreateRegistry",
        "CreateRegistryRecord",
        "DeleteRegistry",
        "DeleteRegistryRecord",
        "DeleteResourcePolicy",
        "GetDiscoverableRegistryRecord",
        "GetRegistry",
        "GetRegistryRecord",
        "GetResourcePolicy",
        "InvokeRegistryMcp",
        "ListDiscoverableRegistryRecords",
        "ListRegistries",
        "ListRegistryRecords",
        "ListTagsForResource",
        "PutResourcePolicy",
        "SearchDiscoverableRegistryRecords",
        "SubmitRegistryRecordForApproval",
        "TagResource",
        "UntagResource",
        "UpdateRegistry",
        "UpdateRegistryRecord",
        "UpdateRegistryRecordStatus",
    )
)


@lru_cache(maxsize=1)
def agentcore_namespace_actions() -> frozenset:
    """List the concrete ``bedrock-agentcore`` action names, lowercased.

    Returns:
        Every action in the namespace known to the IAM action data, used to tell
        whether a policy's patterns reach into the namespace at all.
    """
    # expand_actions returns fully qualified names, so drop the namespace to
    # match the bare-name form the callers rebuild.
    return frozenset(
        action.lower().partition(":")[2]
        for action in expand_actions(
            f"{AGENTCORE_NAMESPACE}:*", InvalidActionHandling.REMOVE
        )
    )


def _effect_of(statement: dict) -> str:
    """A statement's ``Effect``, normalised for comparison against ``"allow"``/``"deny"``.

    Args:
        statement: One IAM policy statement.

    Returns:
        The Effect lowercased and stripped, or ``""`` when absent.

    One reading of Effect for the whole file. Comparing against the exact strings ``"Allow"`` and
    ``"Deny"`` in some places and normalising in others gave the same aggregated statement list two
    different meanings: a non-canonically spelled Deny was KEPT by
    ``statements_with_only_unconditional_denies`` and then SKIPPED by the registry branch, so it never
    subtracted from ``denied`` and a role holding the whole namespace reported FAIL. IAM stores the
    canonical spellings, so that was a latent divergence rather than an observed failure -- which is
    the point of removing it while it still is one. ``check_full_service_access`` normalises the same
    way.
    """
    return str(statement.get("Effect", "")).strip().lower()


def deny_applies_unconditionally(statement: dict) -> bool:
    """Whether a Deny statement cannot fail to apply, so it may cancel an Allow.

    Args:
        statement: One IAM policy statement.

    Returns:
        True when the statement is a Deny whose Resource includes ``"*"``, carries no ``Condition``
        and no ``NotResource``. False for any other statement, including every Allow.

    Why this exists. ``get_effective_actions`` -- and ``check_full_service_access``'s first gate --
    read only Effect, Action and NotAction. Resource and Condition are ignored, so once a role's
    statements are aggregated (which is required for a Deny in one policy to cancel an Allow in
    another) a Deny scoped to a single resource cancels an Allow covering everything. For a security
    check that is a FALSE PASS, and both AgentCore payment actions take a REQUIRED
    ``payment-manager`` resource type and support ``aws:ResourceTag``, so the case is reachable.

    An explicit Deny still wins -- that is IAM, and it is not up for negotiation -- but only where it
    demonstrably bites. A narrower or conditional Deny leaves the capability standing and the finding
    is reported. That errs towards over-reporting on purpose: a Deny scoped to the only resource an
    Allow covers will read as unsuppressed here, which is a false FAIL, and a false FAIL is the
    survivable direction for a separation-of-duties finding.
    """
    if _effect_of(statement) != "deny":
        return False
    if "Condition" in statement or "NotResource" in statement:
        return False
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    return "*" in resources


def statements_with_only_unconditional_denies(statements: list) -> list:
    """Keep every Allow, and only the Deny statements that cannot fail to apply.

    Args:
        statements: The role's aggregated policy statements.

    Returns:
        The subset safe to hand to a Resource-blind evaluator.
    """
    return [
        statement
        for statement in statements
        if _effect_of(statement) != "deny" or deny_applies_unconditionally(statement)
    ]


@lru_cache(maxsize=4096)
def _action_matches(pattern: str, action: str) -> bool:
    """Whether one IAM Action pattern names a concrete action.

    Args:
        pattern: An Action or NotAction pattern, already lowercased.
        action: A concrete ``namespace:actionname`` string, already lowercased.

    Returns:
        True when IAM would consider the pattern to name that action.

    IAM Action matching honours exactly ``*`` and ``?``; every other character is literal. This was
    ``fnmatch``, which additionally implements ``[seq]`` character classes, and the difference was a
    FALSE PASS rather than mere noise because this helper resolves BOTH effects: an over-matching
    pattern in a DENY inflates the denied set, so ``AGENT_REGISTRY_ACTIONS <= (allowed - denied)``
    fails and a role holding the whole namespace is reported as scoped. Measured: a Deny of
    ``agent-registry:[Dd]eleteRegistry`` -- a literal, non-existent action name to IAM, denying
    nothing -- excused a role granting ``agent-registry:*``.
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html

    Matched with a two-pointer scan rather than a translated regex. The first version of this fix
    built ``.*`` for every ``*`` and called ``re.fullmatch``, which backtracks catastrophically:
    a pattern of ``*a`` repeated took 0.03s at 44 characters, 1.9s at 56, 7.6s at 60, and did not
    finish inside 30s at 64. Action patterns come from a policy document the scan reads, so any
    principal able to write a policy could stall the scan indefinitely -- and unlike a raised
    exception, a hang is not even caught by the bare ``except Exception`` in check.py. The
    ``fnmatch`` this replaced did NOT have that behaviour, because ``fnmatch.translate`` emits
    atomic groups; dropping fnmatch for IAM correctness therefore had to bring its own guarantee.
    This scan is O(len(pattern) x len(action)) with no backtracking path at all.
    """
    p = a = 0
    star = resume = -1
    while a < len(action):
        if p < len(pattern) and pattern[p] in ("?", action[a]):
            p += 1
            a += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            resume = a
            p += 1
        elif star >= 0:
            # Backtrack to the most recent star and let it absorb one more character. Only ever
            # one star is reconsidered, which is what bounds this at a product rather than a power.
            resume += 1
            a = resume
            p = star + 1
        else:
            return False
    return all(char == "*" for char in pattern[p:])


class bedrockagentcore_full_access_policy_attached(Check):
    """Ensure IAM roles do not hold full access to Bedrock AgentCore.

    Each IAM role is evaluated for an over-broad AgentCore grant, coming either
    from an AWS-managed full-access policy or from a policy document of its own:

    - FAIL: An attached managed policy ARN ends with ``BedrockAgentCoreFullAccess``
      or ``AgentRegistryFullAccess``.
    - FAIL: An attached or inline policy document has an ``Allow`` statement on
      ``Resource: "*"`` that reaches every action in the ``bedrock-agentcore`` or
      ``agent-registry`` namespace. A grant reaching the whole namespace counts
      however it is written, so ``bedrock-agentcore:*``, ``*``, ``*:*``, and an
      ``Allow`` with ``NotAction`` that excludes nothing in the namespace all
      fail. Matching is case-insensitive, as IAM matches action names.
    - PASS: The role has an AgentCore grant, but a scoped one.
    - MANUAL: The role has an AgentCore grant and at least one of its policy
      documents could not be resolved in the IAM inventory, so the rest of its
      privilege is unknown.

    Roles with no AgentCore-relevant grant at all are skipped rather than
    reported.
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
            report.status_extended = "IAM roles could not be listed, so this check could not be evaluated; verify manually that no role grants full access to Bedrock AgentCore."
            return [report]

        for role in iam_client.roles:
            violations = []
            unresolved = []
            evaluated = False

            # EVERY resolved statement for this role, aggregated before anything is evaluated.
            # IAM evaluates all applicable policies together and an explicit Deny beats an Allow
            # anywhere in the set, so evaluating one document at a time and combining the verdicts
            # loses a Deny in policy B that overrides an Allow in policy A -- and reports FAIL for a
            # role that does not have the permission. check_full_service_access subtracts Deny only
            # within the document it is handed, so handing it the whole role is what makes the
            # subtraction real.
            statements = []
            contributing = []

            for policy in role.attached_policies:
                policy_arn = policy.get("PolicyArn", "")
                policy_name = policy.get("PolicyName") or policy_arn
                managed_namespace = self._managed_full_access_namespace(policy_arn)
                if managed_namespace is not None:
                    # Do NOT report on sight. The AWS-managed documents scope their Resource, so the
                    # name is the only way to establish this Allow -- but an Allow still loses to an
                    # explicit Deny elsewhere on the role. Feed it into the aggregate as the grant it
                    # is and let the single role-level evaluation decide, exactly as for a document.
                    statements.append(
                        {
                            "Effect": "Allow",
                            "Action": f"{managed_namespace}:*",
                            "Resource": "*",
                        }
                    )
                    contributing.append(f"AWS-managed policy {policy_name}")
                    continue
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"managed policy {policy_name}")
                    continue
                document_statements = self._statements_of(policy_obj.document)
                if document_statements:
                    statements.extend(document_statements)
                    contributing.append(f"managed policy {policy_name}")

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"inline policy {inline_name}")
                    continue
                document_statements = self._statements_of(policy_obj.document)
                if document_statements:
                    statements.extend(document_statements)
                    contributing.append(f"inline policy {inline_name}")

            # Rendered in a sorted order rather than the order the two loops happened to visit.
            # ListAttachedRolePolicies and ListRolePolicies document no ordering, so without this
            # one role produces two different status_extended strings across scans and reads as two
            # different findings. Same defect as the delegated-administrator listing, same fix.
            contributing.sort()
            unresolved.sort()

            if statements:
                label = (
                    contributing[0]
                    if len(contributing) == 1
                    else f"{' and '.join(contributing)} together"
                )
                # Same filter as the payments check, and for the same reason:
                # check_full_service_access gates on get_effective_actions first, which is
                # Resource-blind, so a Deny scoped to one gateway would talk it out of a
                # finding about a grant covering every resource.
                relevant, aggregate_violations = self._evaluate_document(
                    {
                        "Version": "2012-10-17",
                        "Statement": statements_with_only_unconditional_denies(
                            statements
                        ),
                    },
                    label,
                )
                evaluated = evaluated or relevant
                violations.extend(aggregate_violations)

            if not evaluated and not unresolved:
                # No AgentCore grant at all: nothing to say about AgentCore
                # privilege, so do not emit noise. A role with an unreadable
                # document is not skipped: the grant that would bring it into
                # scope is exactly what could not be read.
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            # An IAM Role carries no region attribute, so Check_Report_AWS
            # leaves the field empty. IAM is global and its checks report the
            # IAM client region instead, so the status text names no region.
            report.region = iam_client.region

            if violations:
                report.status = "FAIL"
                report.status_extended = f"IAM Role {role.name} grants full access to Bedrock AgentCore: {'; '.join(violations)}."
            elif unresolved:
                report.status = "MANUAL"
                # evaluated is False when no document that could be read
                # granted AgentCore access, so claiming the role grants it would
                # assert something only the unreadable document could establish.
                grants = (
                    "grants Bedrock AgentCore access"
                    if evaluated
                    else "may grant Bedrock AgentCore access"
                )
                report.status_extended = f"IAM Role {role.name} {grants}, but {', '.join(unresolved)} could not be retrieved from the IAM inventory; verify manually that it does not grant full access."
            else:
                report.status = "PASS"
                report.status_extended = f"IAM Role {role.name} grants scoped Bedrock AgentCore access rather than full access."

            findings.append(report)

        return findings

    def _managed_full_access_namespace(self, policy_arn: str):
        """Return the namespace an AWS-managed full-access policy grants, or None.

        Args:
            policy_arn: The attached policy's ARN.

        Returns:
            The IAM namespace the policy grants in full when the ARN is AWS-managed AND its basename
            is exactly one of FULL_ACCESS_POLICY_SUFFIXES; otherwise None.
        """
        # BOTH halves are required. `.endswith(name)` alone matches a CUSTOMER-managed
        # arn:aws:iam::111122223333:policy/TeamBedrockAgentCoreFullAccess, and the caller treats a
        # match as a finding without reading the document -- so a policy granting nothing would FAIL
        # the role. The AWS-managed segment is partition-independent on purpose: GovCloud and China
        # ARNs are arn:aws-us-gov: and arn:aws-cn:, so an "arn:aws:" prefix test would silently stop
        # matching there. The sibling check bedrockagentcore_tool_execution_role_no_wildcard_privileges
        # already guards this way; this check did not, which is what made it a defect.
        if ":iam::aws:policy/" not in policy_arn:
            return None
        return FULL_ACCESS_POLICY_NAMESPACE.get(policy_arn.rsplit("/", 1)[-1])

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

    def _evaluate_document(self, document: dict, label: str) -> tuple:
        """Evaluate one policy document for an over-broad AgentCore grant.

        Args:
            document: The IAM policy document.
            label: How to refer to this policy in the finding text.

        Returns:
            A tuple of (relevant, violations): whether the document grants any
            AgentCore action at all, and the violation strings it produced.
        """
        statements = document.get("Statement")
        # A single-statement document may carry the statement as a bare dict.
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return False, []
        statements = [
            statement for statement in statements if isinstance(statement, dict)
        ]

        relevant = any(
            self._statement_touches_agentcore(statement)
            for statement in statements
            if _effect_of(statement) == "allow"
        )

        namespaces = [
            namespace
            for namespace in AGENTCORE_NAMESPACES
            if self._grants_whole_namespace(
                namespace, {**document, "Statement": statements}
            )
        ]
        if not namespaces:
            return relevant, []

        # Reaching a whole namespace is itself an AgentCore grant, even when no
        # statement names the namespace literally (Action "*" for example), so
        # the role must be reported rather than skipped.
        return True, [
            f"{label} allows {', '.join(f'{namespace}:*' for namespace in namespaces)} on all resources"
        ]

    def _grants_whole_namespace(self, namespace: str, document: dict) -> bool:
        """Check whether a document grants every action in a namespace on ``*``.

        Args:
            namespace: The AgentCore IAM namespace, without the trailing colon.
            document: The IAM policy document, statements already normalised.

        Returns:
            True when the document allows the whole namespace on Resource ``*``.
        """
        if namespace == AGENTCORE_NAMESPACE:
            # check_full_service_access expands every Action and NotAction
            # pattern to concrete action names, subtracts the Deny statements,
            # and requires Resource "*", so wildcards in any position, "*",
            # "*:*", and NotAction are all resolved by it.
            return check_full_service_access(namespace, document)

        # The registry namespace has no expansion data behind
        # check_full_service_access, so resolve the grant against the documented
        # action list instead and ask the same question: does every action in the
        # namespace end up allowed on Resource "*"?
        allowed = set()
        denied = set()
        for statement in document.get("Statement", []):
            effect = _effect_of(statement)
            if effect not in ("allow", "deny"):
                continue
            # A Deny counts wherever it applies; only the Allow needs Resource
            # "*" to constitute full access.
            if effect == "allow" and "*" not in self._as_list(
                statement.get("Resource")
            ):
                continue
            matched = self._matched_actions(
                statement, namespace, AGENT_REGISTRY_ACTIONS
            )
            if effect == "allow":
                allowed |= matched
            else:
                denied |= matched

        return AGENT_REGISTRY_ACTIONS <= (allowed - denied)

    def _matched_actions(self, statement: dict, namespace: str, actions) -> set:
        """Resolve a statement's Action/NotAction against concrete action names.

        Args:
            statement: A single policy statement.
            namespace: The IAM namespace the actions belong to.
            actions: The concrete lowercase action names to match against.

        Returns:
            The subset of ``actions`` this statement's patterns match.
        """
        patterns = self._as_list(statement.get("Action"))
        matched = {
            action
            for action in actions
            for pattern in patterns
            if _action_matches(pattern.lower(), f"{namespace}:{action}")
        }

        # An Allow with NotAction covers every action its patterns do not match.
        not_action_patterns = self._as_list(statement.get("NotAction"))
        if not_action_patterns:
            matched |= {
                action
                for action in actions
                if not any(
                    _action_matches(pattern.lower(), f"{namespace}:{action}")
                    for pattern in not_action_patterns
                )
            }

        return matched

    def _statement_touches_agentcore(self, statement: dict) -> bool:
        """Check whether a statement grants any AgentCore action at all.

        Args:
            statement: A single policy statement.

        Returns:
            True when an Action or NotAction pattern matches at least one action
            in either AgentCore namespace, which makes the role this check's
            business.
        """
        return any(
            self._matched_actions(statement, namespace, actions)
            for namespace, actions in (
                (AGENTCORE_NAMESPACE, agentcore_namespace_actions()),
                (AGENT_REGISTRY_NAMESPACE, AGENT_REGISTRY_ACTIONS),
            )
        )

    def _as_list(self, value) -> list:
        """Normalise an Action, NotAction, or Resource value to a list of strings.

        Args:
            value: A string, a list, or something else entirely.

        Returns:
            A list of the string entries in the value.
        """
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, str)]
        return []
