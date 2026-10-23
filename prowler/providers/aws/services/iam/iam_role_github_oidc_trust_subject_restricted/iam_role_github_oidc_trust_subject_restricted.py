from collections.abc import Iterable

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"
GITHUB_OIDC_PROVIDER = f"oidc-provider/{GITHUB_OIDC_HOST}"
GITHUB_SUB_KEY = f"{GITHUB_OIDC_HOST}:sub"
WEB_IDENTITY_ACTION = "sts:AssumeRoleWithWebIdentity"


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _has_github_provider(principal: object) -> bool:
    if not isinstance(principal, dict):
        return False
    return any(
        str(provider).endswith(f"/{GITHUB_OIDC_HOST}")
        for provider in _as_list(principal.get("Federated"))
    )


def _has_web_identity_action(action: object) -> bool:
    return WEB_IDENTITY_ACTION in _as_list(action) or any(
        value in {"sts:*", "*"} for value in _as_list(action)
    )


def _subject_values(condition: object) -> tuple[list, bool]:
    """Return sub values and whether their operators strictly enforce presence."""
    if not isinstance(condition, dict):
        return [], False

    values = []
    strict_operator_seen = False
    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue
        for key, value in entries.items():
            if key != GITHUB_SUB_KEY:
                continue
            operator = str(operator)
            base_operator = operator.removeprefix("ForAnyValue:")
            if base_operator not in {"StringEquals", "StringLike"}:
                return [], False
            strict_operator_seen = True
            values.extend(_as_list(value))
    return values, strict_operator_seen


def _subject_is_restricted(values: Iterable) -> bool:
    values = list(values)
    if not values:
        return False
    for value in values:
        if not isinstance(value, str) or not value.startswith("repo:"):
            return False
        parts = value[5:].split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return False
        owner_repo = parts[0].split("/")
        if len(owner_repo) != 2:
            return False
        owner, repository = owner_repo
        if not owner or not repository or not parts[1] or "*" in owner or "?" in owner:
            return False
    return True


class iam_role_github_oidc_trust_subject_restricted(Check):
    """Ensure GitHub Actions OIDC trust policies pin the repository owner."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for role in iam_client.roles or []:
            statements = role.assume_role_policy.get("Statement", [])
            statements = _as_list(statements)
            in_scope = [
                statement
                for statement in statements
                if isinstance(statement, dict)
                and statement.get("Effect") == "Allow"
                and _has_web_identity_action(statement.get("Action"))
                and _has_github_provider(statement.get("Principal"))
            ]
            if not in_scope:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region
            compliant = True
            for statement in in_scope:
                values, strict_operator_seen = _subject_values(statement.get("Condition"))
                if not strict_operator_seen or not _subject_is_restricted(values):
                    compliant = False
                    break

            report.status = "PASS" if compliant else "FAIL"
            if compliant:
                report.status_extended = (
                    f"IAM Role {role.name} restricts GitHub Actions OIDC trust to specific repository owners."
                )
            else:
                report.status_extended = (
                    f"IAM Role {role.name} allows GitHub Actions OIDC trust without a strictly restricted repository owner in the sub claim."
                )
            findings.append(report)
        return findings
