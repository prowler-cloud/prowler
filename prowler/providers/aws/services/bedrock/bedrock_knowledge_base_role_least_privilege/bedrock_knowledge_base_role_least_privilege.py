from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    _get_patterns_from_standard_value,
    check_full_service_access,
    iam_pattern_matches,
)


def _unscoped_deny_patterns(document: dict) -> set[str]:
    """Collect action patterns of unscoped explicit Deny statements.

    A Deny counts as unscoped only when it has no ``Condition``, no
    ``NotResource``, and ``Resource: "*"`` -- a narrower Deny leaves the Allow
    exercisable on everything else, so it must not cancel a finding.
    """
    denies = set()
    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "")).strip().lower()
        if effect != "deny":
            continue
        patterns = _get_patterns_from_standard_value(statement.get("Action"))
        if not patterns:
            continue
        deny_resources = _get_patterns_from_standard_value(statement.get("Resource"))
        if (
            "Condition" not in statement
            and "NotResource" not in statement
            and any(r.strip() == "*" for r in deny_resources)
        ):
            denies.update(patterns)
    return denies


def _broad_bedrock_violations(document: dict, deny_patterns: set[str]) -> list[str]:
    """Find least-privilege violations in one IAM policy document.

    A violation is reported when an ``Allow`` statement:
    - grants full Bedrock access (``bedrock:*``-equivalent) on all resources,
      evaluated Deny-aware via :func:`check_full_service_access`; or
    - uses a ``bedrock:*`` (or ``*``) action wildcard at all; or
    - grants any Bedrock action on ``Resource: "*"`` instead of scoping it to
      the knowledge base / data source resources it needs.

    ``deny_patterns`` holds the action patterns of every unscoped explicit
    Deny collected across ALL readable policies of the role. IAM evaluates a
    role's identity policies together, so an unscoped Deny in one policy
    cancels a flagged Allow in another: Deny always wins, and the check must
    not FAIL on a permission that cannot actually be exercised. A Deny counts
    as unscoped only when it has no ``Condition``, no ``NotResource``, and
    ``Resource: "*"`` -- a narrower Deny leaves the Allow exercisable on
    everything else, so it must not turn the finding into a PASS.
    """
    violations = []

    if check_full_service_access("bedrock", document):
        return ["grants full Bedrock access (bedrock:*) on all resources"]

    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    wildcard_actions = set()
    broad_resource_actions = set()
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "")).strip().lower()
        if effect != "allow":
            continue
        patterns = _get_patterns_from_standard_value(statement.get("Action"))
        if not patterns:
            continue
        resources = _get_patterns_from_standard_value(statement.get("Resource"))
        for pattern in patterns:
            normalized = pattern.strip().lower()
            is_bedrock = normalized == "*" or normalized.startswith("bedrock:")
            if not is_bedrock:
                continue
            is_wildcard = normalized in ("*", "bedrock:*") or (
                normalized.startswith("bedrock:") and normalized.endswith("*")
            )
            if is_wildcard:
                wildcard_actions.add(pattern)
            elif any(resource.strip() == "*" for resource in resources):
                broad_resource_actions.add(pattern)

    for pattern in sorted(wildcard_actions):
        # An unscoped explicit Deny for the same or a broader action pattern
        # cancels the violation: the permission cannot be exercised.
        if not any(iam_pattern_matches(deny, pattern) for deny in deny_patterns):
            violations.append(f"grants '{pattern}' action wildcard")
    for pattern in sorted(broad_resource_actions):
        if not any(iam_pattern_matches(deny, pattern) for deny in deny_patterns):
            violations.append(f"grants '{pattern}' on all resources (*)")

    return violations


class bedrock_knowledge_base_role_least_privilege(Check):
    """Ensure Bedrock Knowledge Base service roles follow least privilege.

    A Bedrock Knowledge Base's service role is evaluated against the effective
    statements of its attached managed and inline IAM policies:
    - No policy may grant ``bedrock:*`` (full Bedrock access) or any other
      Bedrock action wildcard.
    - Bedrock actions must be scoped to the knowledge base / data source
      resources they need, not granted on ``Resource: "*"``.
    - Explicit ``Deny`` statements are honoured across the role: an unscoped
      Deny (no ``Condition``/``NotResource``, ``Resource: "*"``) in any
      readable policy means the permission cannot be exercised, so it is not
      a violation; a scoped Deny does not cancel the finding.

    One finding is reported per knowledge base. The status is ``FAIL`` when any
    of the criteria above is violated and ``MANUAL`` when the service role
    cannot be retrieved or resolved in IAM. When the IAM role inventory itself
    could not be listed, a single account-level ``MANUAL`` report is returned
    instead. Knowledge bases that could not be listed in a region are reported
    per region as ``MANUAL``. A policy whose document cannot be retrieved
    makes the finding ``MANUAL`` when no violation was found in a readable
    policy; a real violation still reports ``FAIL``.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Run the least-privilege evaluation across all Bedrock Knowledge Bases.

        Returns:
            A list of ``Check_Report_AWS`` with one entry per knowledge base.
        """
        findings = []

        for region, error in sorted(
            bedrock_agent_client.knowledge_bases_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "knowledge-base/unknown"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:knowledge-base/unknown"
            report.status = "MANUAL"
            report.status_extended = (
                f"Bedrock knowledge bases could not be listed in region {region} "
                f"({error}); verify manually that every knowledge base service "
                f"role follows least privilege."
            )
            findings.append(report)

        if iam_client.roles is None and bedrock_agent_client.knowledge_bases:
            # iam:ListRoles was denied: this is an account-wide condition, so
            # emit one account-level MANUAL instead of one per knowledge base.
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.audited_account_arn
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate Bedrock Knowledge Base service roles: the IAM roles could not be listed. Verify that the scanning credentials are allowed to call iam:ListRoles."
            findings.append(report)
            return findings

        roles_by_arn = {role.arn: role for role in (iam_client.roles or [])}

        for knowledge_base in bedrock_agent_client.knowledge_bases.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=knowledge_base)
            report.resource_id = knowledge_base.id
            report.resource_arn = knowledge_base.arn
            report.status = "PASS"
            report.status_extended = (
                f"Bedrock knowledge base {knowledge_base.name} service role "
                f"follows least privilege."
            )

            if not knowledge_base.detail_retrieved or not knowledge_base.role_arn:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock knowledge base {knowledge_base.name} service role "
                    f"could not be retrieved in region {knowledge_base.region} and "
                    f"cannot be evaluated for least privilege; verify the role "
                    f"manually."
                )
                findings.append(report)
                continue

            role = roles_by_arn.get(knowledge_base.role_arn)
            if role is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock knowledge base {knowledge_base.name} service role "
                    f"could not be resolved in IAM and cannot be evaluated for "
                    f"least privilege; verify the role manually."
                )
                findings.append(report)
                continue

            violations = []
            unreadable = []

            # IAM evaluates all of a role's identity policies together, so an
            # unscoped explicit Deny in ANY readable policy cancels a flagged
            # Allow in another one. Collect the readable documents and the
            # role-wide unscoped denies first, then evaluate each policy
            # against the full deny set.
            readable = []
            role_denies = set()

            for policy in role.attached_policies:
                policy_name = policy.get("PolicyName") or policy.get("PolicyArn", "")
                policy_arn = policy.get("PolicyArn", "")
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    # The policy reference exists on the role but its document
                    # could not be retrieved (GetPolicyVersion failed): the
                    # check cannot evaluate it, so the finding must not be a
                    # silent PASS. It becomes MANUAL below unless a violation
                    # was found in a readable policy.
                    unreadable.append(f"managed policy {policy_name}")
                    continue
                readable.append((f"managed policy {policy_name}", policy_obj.document))
                role_denies |= _unscoped_deny_patterns(policy_obj.document)

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    unreadable.append(f"inline policy {inline_name}")
                    continue
                readable.append((f"inline policy {inline_name}", policy_obj.document))
                role_denies |= _unscoped_deny_patterns(policy_obj.document)

            for label, document in readable:
                for violation in _broad_bedrock_violations(document, role_denies):
                    violations.append(f"{label} {violation}")

            if violations:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock knowledge base {knowledge_base.name} service role "
                    f"violates least privilege: {'; '.join(violations)}."
                )
            elif unreadable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock knowledge base {knowledge_base.name} service role "
                    f"policies could not be read ({', '.join(unreadable)}); "
                    f"verify the role manually."
                )

            findings.append(report)

        return findings
