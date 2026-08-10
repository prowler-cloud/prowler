from typing import Dict, List, Set

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


def _parse_assume_role_principals(trust_policy: dict) -> Set[str]:
    """Extract role ARNs allowed to assume this role from trust policy."""
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
        principal = stmt.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if isinstance(p, str) and ":role/" in p:
                principals.add(p)
            if isinstance(p, str) and p.endswith(":root"):
                principals.add(p)
    return principals


def _get_role_effective_document(role_name: str) -> List[dict]:
    """Collect all effective policy documents for a role."""
    docs = []
    for policy_obj in iam_client.policies.values():
        if policy_obj.entity == role_name and policy_obj.attached:
            if policy_obj.document:
                docs.append(policy_obj.document)
    return docs


class iam_role_chained_privilege_escalation(Check):
    """Detect chained escalation where a role can assume a privileged role."""

    def execute(self) -> List[Check_Report_AWS]:
        """Detect two directions: source assumes privileged target, and privileged assumable by in-account role."""
        findings = []

        if not iam_client.roles:
            return findings

        role_by_arn: Dict[str, object] = {r.arn: r for r in iam_client.roles}

        # Cache effective documents once per role
        role_docs_map: Dict[str, List[dict]] = {}
        for r in iam_client.roles:
            role_docs_map[r.name] = _get_role_effective_document(r.name)

        # Pre-compute privileged roles
        role_has_privesc: Dict[str, Set[str]] = {}
        for role in iam_client.roles:
            affected_all = set()
            for doc in role_docs_map.get(role.name, []):
                affected = check_privilege_escalation(doc)
                if affected:
                    affected_all.add(affected)
            if affected_all:
                role_has_privesc[role.arn] = affected_all

        root_arn = f"arn:aws:iam::{iam_client.audited_account}:root"

        for role in iam_client.roles:
            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.resource_id = role.name
            report.resource_arn = role.arn
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = f"IAM role {role.name} does not allow chained privilege escalation."

            # Direction 1: source can assume privileged target via its own policies, target trust must allow source
            assumable_privileged = []
            for doc in role_docs_map.get(role.name, []):
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
                    if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
                        continue
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    for res in resources:
                        for target_arn, priv_techniques in role_has_privesc.items():
                            if target_arn == role.arn:
                                continue
                            if not (
                                res == "*"
                                or res == target_arn
                                or (res.endswith("*") and target_arn.startswith(res[:-1]))
                            ):
                                continue
                            target_role = role_by_arn.get(target_arn)
                            if not target_role:
                                continue
                            trusted = _parse_assume_role_principals(
                                getattr(target_role, "assume_role_policy", None)
                            )
                            if role.arn in trusted or root_arn in trusted:
                                assumable_privileged.append((target_arn, priv_techniques))

            if assumable_privileged:
                # Deduplicate targets
                seen = set()
                deduped = []
                for arn, techs in assumable_privileged:
                    if arn not in seen:
                        deduped.append((arn, techs))
                        seen.add(arn)
                targets = ", ".join(
                    [f"{arn.split('/')[-1]} via {sorted(list(techs))}" for arn, techs in deduped]
                )
                report.status = "FAIL"
                report.status_extended = f"IAM role {role.name} can assume privileged role(s) and escalate: {targets}."
            else:
                # Direction 2: privileged role is assumable by in-account roles
                if role.arn in role_has_privesc:
                    principals = _parse_assume_role_principals(role.assume_role_policy)
                    if principals:
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
