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


def _broad_bedrock_violations(document: dict) -> list[str]:
    """Find least-privilege violations in one IAM policy document.

    A violation is reported when an ``Allow`` statement:
    - grants full Bedrock access (``bedrock:*``-equivalent) on all resources,
      evaluated Deny-aware via :func:`check_full_service_access`; or
    - uses a ``bedrock:*`` (or ``*``) action wildcard at all; or
    - grants any Bedrock action on ``Resource: "*"`` instead of scoping it to
      the knowledge base / data source resources it needs.

    An explicit ``Deny`` for the same (or a broader) action pattern cancels a
    flagged ``Allow``: Deny always wins in IAM, and the check must not FAIL on
    a permission that cannot actually be exercised.
    """
    violations = []

    if check_full_service_access("bedrock", document):
        return ["grants full Bedrock access (bedrock:*) on all resources"]

    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    deny_patterns = set()
    wildcard_actions = set()
    broad_resource_actions = set()
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "")).strip().lower()
        patterns = _get_patterns_from_standard_value(statement.get("Action"))
        if not patterns:
            continue
        if effect == "deny":
            deny_patterns.update(patterns)
            continue
        if effect != "allow":
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
        # An explicit Deny for the same or a broader action pattern cancels
        # the violation: the permission cannot be exercised.
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
    - Explicit ``Deny`` statements are honoured: a denied permission is not a
      violation.

    One finding is reported per knowledge base. The status is ``FAIL`` when any
    of the criteria above is violated and ``MANUAL`` when the service role
    cannot be retrieved or resolved in IAM. When the IAM role inventory itself
    could not be listed, a single account-level ``MANUAL`` report is returned
    instead. Knowledge bases that could not be listed in a region are reported
    per region as ``MANUAL``.
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

            for policy in role.attached_policies:
                policy_name = policy.get("PolicyName") or policy.get("PolicyArn", "")
                policy_arn = policy.get("PolicyArn", "")
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    continue
                for violation in _broad_bedrock_violations(policy_obj.document):
                    violations.append(f"managed policy {policy_name} {violation}")

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    continue
                for violation in _broad_bedrock_violations(policy_obj.document):
                    violations.append(f"inline policy {inline_name} {violation}")

            if violations:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock knowledge base {knowledge_base.name} service role "
                    f"violates least privilege: {'; '.join(violations)}."
                )

            findings.append(report)

        return findings
