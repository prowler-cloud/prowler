"""IAM role chained privilege escalation check.

Detects transitive escalation where a low-privileged role can sts:AssumeRole
into a privileged role that itself can escalate to admin. Supports multi-hop
chains by building an assume-role graph and performing BFS.
"""

import fnmatch
import re
from collections import deque
from typing import Dict, List, Set

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ISSUE_CONDITION_MSG = "conditional trust skipped"


def _normalize_account_principal(principal: str) -> str:
    """Normalize bare AWS account IDs to root ARN.

    Args:
        principal: AWS principal string, may be bare 12-digit account ID.

    Returns:
        Normalized ARN for account root if bare ID, otherwise original.
    """
    if _ACCOUNT_ID_RE.match(principal):
        # Default to aws partition; partition-aware matching handles other partitions downstream
        return f"arn:aws:iam::{principal}:root"
    return principal


def _parse_assume_role_principals(trust_policy: dict) -> Set[str]:
    """Extract AWS role ARNs allowed to assume this role.

    Parses IAM trust policy statements and returns ARNs of principals
    allowed to assume the role, plus a sentinel wildcard entry.

    Handles bare 12-digit account IDs by normalizing to root ARN and skips
    statements that contain Condition for conservative evaluation.

    Args:
        trust_policy: IAM trust policy document from AssumeRolePolicyDocument.

    Returns:
        Set of ARN strings for principals that can assume the role,
        including account root ARNs and a wildcard "*" when trust
        is unconditioned and allows any principal.
    """
    principals = set()
    if not trust_policy:
        return principals
    statements = trust_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
            continue
        # Conservative handling for conditional trust: if Condition present, skip
        # because trust is not unconditionally granted. Only allow wildcard when Condition absent.
        if "Condition" in stmt:
            continue
        principal = stmt.get("Principal", {})
        # Handle Principal as string wildcard
        if isinstance(principal, str):
            if principal == "*":
                principals.add("*")
            continue
        if not isinstance(principal, dict):
            continue
        # Handle Principal dict containing star key or wildcard value
        if "*" in principal:
            principals.add("*")
            continue
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if not isinstance(p, str):
                continue
            if p == "*":
                principals.add("*")
                continue
            # Normalize bare account IDs like "123456789012" to root ARN
            normalized = _normalize_account_principal(p)
            if ":role/" in normalized or normalized.endswith(":root") or _ACCOUNT_ID_RE.match(p):
                # For bare account IDs we already normalized
                principals.add(normalized)
            elif normalized != p and _ACCOUNT_ID_RE.match(p):
                principals.add(normalized)
    return principals


def _is_root_trusted(trusted_set: Set[str], audited_account: str) -> bool:
    """Check if any trusted principal is a partition-aware root ARN for the account.

    Args:
        trusted_set: Set of trusted principal ARNs.
        audited_account: Account ID string.

    Returns:
        True if a root ARN matching the audited account exists in any partition.
    """
    if not audited_account:
        return False
    for p in trusted_set:
        if p.endswith(":root") and audited_account in p:
            return True
    return False


def _get_role_effective_documents(role) -> List[dict]:
    """Collect effective policy documents for a role including managed policies.

    Looks up inline policy documents stored in iam_client.policies where
    entity equals role name and also resolves attached managed policies
    via role.attached_policies.

    Args:
        role: IAM Role model with name, arn, attached_policies.

    Returns:
        List of policy documents attached to the role.
    """
    docs: List[dict] = []
    role_name = getattr(role, "name", None)
    if not role_name:
        return docs
    # Inline policies stored in iam_client.policies with entity == role name
    for policy_obj in iam_client.policies.values():
        if getattr(policy_obj, "entity", None) == role_name and getattr(
            policy_obj, "attached", False
        ):
            doc = getattr(policy_obj, "document", None)
            if doc:
                docs.append(doc)
    # Attached managed policies via role.attached_policies list of dicts
    attached = getattr(role, "attached_policies", []) or []
    for att in attached:
        arn = None
        name = None
        if isinstance(att, dict):
            arn = att.get("PolicyArn")
            name = att.get("PolicyName")
        else:
            arn = getattr(att, "arn", None)
            name = getattr(att, "name", None)
        if arn:
            pol = iam_client.policies.get(arn)
            if pol and getattr(pol, "document", None):
                docs.append(pol.document)
            else:
                # Fallback search by arn attribute
                for p in iam_client.policies.values():
                    if getattr(p, "arn", None) == arn and getattr(
                        p, "document", None
                    ):
                        docs.append(p.document)
                        break
        elif name:
            for p in iam_client.policies.values():
                if getattr(p, "name", None) == name and getattr(
                    p, "document", None
                ):
                    docs.append(p.document)
                    break
    return docs


def _collect_deny_assume_patterns(docs: List[dict]) -> List[str]:
    """Collect explicit Deny patterns for sts:AssumeRole actions.

    Args:
        docs: List of policy documents.

    Returns:
        List of resource pattern strings that are denied.
    """
    denied = []
    for doc in docs:
        if not doc:
            continue
        statements = doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Deny":
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
                if isinstance(res, str):
                    denied.append(res)
    return denied


class iam_role_chained_privilege_escalation(Check):
    """Check for IAM role chains allowing privilege escalation.

    Evaluates two detection directions plus multi-hop transitive closure:
    1. Source role can assume a privileged target role via sts:AssumeRole.
    2. Privileged role is assumable by in-account roles through trust.
    3. Transitive chains where source assumes intermediate that assumes privileged.

    This fills the gap noted in the privilege escalation library where
    transitive paths were not evaluated.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the IAM chained escalation detection.

        Returns:
            List of Check_Report_AWS with PASS or FAIL findings per role.
        """
        findings: List[Check_Report_AWS] = []

        if not iam_client.roles:
            return findings

        role_by_arn: Dict[str, object] = {r.arn: r for r in iam_client.roles}

        # Cache effective documents once per role for performance
        role_docs_map: Dict[str, List[dict]] = {}
        role_deny_map: Dict[str, List[str]] = {}
        for r in iam_client.roles:
            docs = _get_role_effective_documents(r)
            role_docs_map[r.name] = docs
            role_deny_map[r.arn] = _collect_deny_assume_patterns(docs)

        # Cache trust principals per role
        trust_map: Dict[str, Set[str]] = {}
        for r in iam_client.roles:
            trust_map[r.arn] = _parse_assume_role_principals(
                getattr(r, "assume_role_policy", None)
            )

        # Pre-compute privileged roles from combined effective permissions
        role_has_privesc: Dict[str, Set[str]] = {}
        for role in iam_client.roles:
            docs = role_docs_map.get(role.name, [])
            combined_stmts: List[dict] = []
            for doc in docs:
                if not doc:
                    continue
                statements = doc.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    combined_stmts.append(stmt)
            if not combined_stmts:
                continue
            combined_policy = {
                "Version": "2012-10-17",
                "Statement": combined_stmts,
            }
            affected = check_privilege_escalation(combined_policy)
            if affected:
                # Convert comma-separated string into set of techniques
                techniques = set()
                for part in affected.split(","):
                    t = part.strip().strip("'\" ")
                    if t:
                        techniques.add(t)
                if techniques:
                    role_has_privesc[role.arn] = techniques
                else:
                    # Fallback preserve raw string as single entry
                    role_has_privesc[role.arn] = {affected.strip()}

        audited_account = getattr(iam_client, "audited_account", "")

        # Build full assume graph for BFS (any role to any role) — single construction
        full_assumable: Dict[str, Set[str]] = {}
        for role in iam_client.roles:
            full_set = set()
            docs = role_docs_map.get(role.name, [])
            deny_patterns = role_deny_map.get(role.arn, [])
            for doc in docs:
                if not doc:
                    continue
                statements = doc.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if not any(
                        a in ("sts:AssumeRole", "sts:*", "*") for a in actions
                    ):
                        continue
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    for res in resources:
                        if not isinstance(res, str):
                            continue
                        for target_role in iam_client.roles:
                            if target_role.arn == role.arn:
                                continue
                            # fnmatch wildcard support for ARN patterns
                            if not fnmatch.fnmatch(target_role.arn, res) and res != target_role.arn and res != "*":
                                # Backward compatible exact and simple star handling fallback via fnmatch already covers "*"
                                continue
                            # Explicit Deny handling
                            denied = False
                            for dpat in deny_patterns:
                                if fnmatch.fnmatch(target_role.arn, dpat) or dpat == "*" or dpat == target_role.arn:
                                    denied = True
                                    break
                            if denied:
                                continue
                            trusted = trust_map.get(target_role.arn, set())
                            if (
                                role.arn in trusted
                                or _is_root_trusted(trusted, audited_account)
                                or "*" in trusted
                            ):
                                full_set.add(target_role.arn)
            if full_set:
                full_assumable[role.arn] = full_set

        for role in iam_client.roles:
            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.resource_id = role.name
            report.resource_arn = role.arn
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = (
                f"IAM role {role.name} does not allow chained privilege escalation."
            )

            # Direction 1 with transitive support: source can assume privileged via chain
            reachable_privileged: Dict[str, Set[str]] = {}
            visited = set()
            queue = deque(full_assumable.get(role.arn, []))
            # BFS using deque for performance
            while queue:
                current_arn = queue.popleft()
                if current_arn in visited:
                    continue
                visited.add(current_arn)
                if current_arn in role_has_privesc:
                    reachable_privileged[current_arn] = role_has_privesc[current_arn]
                # Continue traversing even if current is privileged to find deeper chains
                for nxt in full_assumable.get(current_arn, []):
                    if nxt not in visited:
                        queue.append(nxt)

            if reachable_privileged:
                deduped = list(reachable_privileged.items())
                targets = ", ".join(
                    [
                        f"{arn.split('/')[-1]} via {sorted(list(techs))}"
                        for arn, techs in deduped
                    ]
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM role {role.name} can assume privileged role(s) and escalate: {targets}."
                )
            else:
                # Direction 2: privileged role is assumable by in-account roles
                if role.arn in role_has_privesc:
                    principals = trust_map.get(role.arn, set())
                    if principals:
                        in_account_assumers = [
                            p for p in principals if p in role_by_arn
                        ]
                        # Also consider wildcard trust as expanding to in-account
                        if "*" in principals and len(iam_client.roles) > 1:
                            # Treat as assumable if more than one role exists
                            in_account_assumers.append("wildcard-any-principal")
                        # Root trust handling is already partition-aware via _is_root_trusted; include generic root
                        if _is_root_trusted(principals, audited_account) and len(iam_client.roles) > 1:
                            # If root is trusted, any in-account role could potentially assume via root delegation
                            # Keep conservative: only flag when explicit role ARN trusted, wildcard case already covered
                            pass
                        if in_account_assumers:
                            display_assumers = []
                            for a in in_account_assumers:
                                if a == "wildcard-any-principal":
                                    display_assumers.append("any-principal-wildcard")
                                else:
                                    display_assumers.append(a.split("/")[-1])
                            report.status = "FAIL"
                            report.status_extended = (
                                f"IAM role {role.name} allows privilege escalation using actions {sorted(list(role_has_privesc[role.arn]))} "
                                f"and is assumable by in-account roles {', '.join(display_assumers)}, "
                                f"creating a chained escalation path."
                            )

            findings.append(report)

        return findings
