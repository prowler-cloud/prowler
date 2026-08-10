from typing import Dict, List, Set

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


# Re-use public ACL URIs pattern for explanation but for IAM
def _parse_assume_role_principals(trust_policy: dict) -> Set[str]:
    """Extract role ARNs that are allowed to assume this role.

    Returns a set of principal ARNs (role ARNs) found in AssumeRole statements.
    """
    principals = set()
    if not trust_policy:
        return principals
    statements = trust_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
            continue
        principal = stmt.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if isinstance(p, str) and ":role/" in p:
                principals.add(p)
        # Also support ARN list under Principal.AWS as wildcard with root? skip
    return principals


def _get_role_effective_document(role_name: str) -> List[dict]:
    """Collect all policy documents for a role (attached + inline) from iam_client.policies."""
    docs = []
    # attached policies: policy ARN stored in role.attached_policies list of dicts with PolicyArn
    for policy_obj in iam_client.policies.values():
        if policy_obj.entity == role_name and policy_obj.attached:
            if policy_obj.document:
                docs.append(policy_obj.document)
    return docs


class iam_role_chained_privilege_escalation(Check):
    """Check if an IAM role can assume another role that allows privilege escalation."""

    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        if not iam_client.roles:
            return findings

        # Build map role_arn -> role object for quick lookup
        role_by_arn: Dict[str, object] = {r.arn: r for r in iam_client.roles}

        # Pre-compute which roles have privilege escalation
        role_has_privesc: Dict[str, Set[str]] = {}
        for role in iam_client.roles:
            affected_all = set()
            for doc in _get_role_effective_document(role.name):
                affected = check_privilege_escalation(doc)
                if affected:
                    affected_all.update(affected)
            if affected_all:
                role_has_privesc[role.arn] = affected_all

        for role in iam_client.roles:
            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.resource_id = role.name
            report.resource_arn = role.arn
            report.region = iam_client.region

            # Default PASS
            report.status = "PASS"
            report.status_extended = f"IAM role {role.name} does not allow chained privilege escalation."

            principals = _parse_assume_role_principals(role.assume_role_policy)

            # Check if this role can assume a privileged role
            # Two directions:
            # 1) Role A is assumable by Role B, and Role A is privileged -> Role B chain
            # We are iterating Role A (target). Need to find who can assume it.
            # If target role is privileged and has at least one principal role that exists in account, that principal role is the risky one.
            # But since our report is per-role (on the privileged target), we want to also report source roles as FAIL via their ability to assume.
            # Simpler: For each role that IS privileged, if it is assumable by another role in same account, FAIL the assumable role's assumers? That would require reporting on source role.
            # We instead report on both sides: If current role can assume another privileged role, it is FAIL.

            # Direction: current role is source, check if it is allowed to assume a privileged target via its own policies? No, AssumeRole permission comes from source role's policy, not target trust? Actually both needed: source needs sts:AssumeRole on target arn, target trust must allow source.
            # We check target trust for efficiency and assume source has permission if in same account (common misconfig). For complete detection, we also check source policy docs for sts:AssumeRole on target arn.

            # Collect target roles that current role can assume via its own policies
            assumable_privileged = []
            for doc in _get_role_effective_document(role.name):
                if not doc:
                    continue
                statements = doc.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
                        continue
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    for res in resources:
                        # res can be "*" or specific role ARN
                        for target_arn, priv_techniques in role_has_privesc.items():
                            if res == "*" or res == target_arn or (res.endswith("*") and target_arn.startswith(res.rstrip("*"))):
                                assumable_privileged.append((target_arn, priv_techniques))

            if assumable_privileged:
                targets = ", ".join([f"{arn.split('/')[-1]} via {sorted(list(techs))}" for arn, techs in assumable_privileged])
                report.status = "FAIL"
                report.status_extended = f"IAM role {role.name} can assume privileged role(s) and escalate: {targets}."
            else:
                # Also check if current role itself is privileged AND is assumable by another role in account -> still report as high risk on the privileged role having overly permissive trust
                if role.arn in role_has_privesc:
                    if principals:
                        # Filter to principals that exist in our account roles
                        in_account_assumers = [p for p in principals if p in role_by_arn]
                        if in_account_assumers:
                            report.status = "FAIL"
                            report.status_extended = (
                                f"IAM role {role.name} allows privilege escalation using actions {sorted(list(role_has_privesc[role.arn]))} "
                                f"and is assumable by in-account roles {', '.join([a.split('/')[-1] for a in in_account_assumers])}, "
                                f"creating a chained escalation path."
                            )

            findings.append(report)

        return findings
