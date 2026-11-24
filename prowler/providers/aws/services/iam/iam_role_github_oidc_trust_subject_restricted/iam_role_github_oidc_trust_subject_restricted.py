from collections.abc import Iterable
from fnmatch import fnmatchcase

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"
GITHUB_SUB_KEY = f"{GITHUB_OIDC_HOST}:sub"
WEB_IDENTITY_ACTION = "sts:AssumeRoleWithWebIdentity"


def _as_list(value: object) -> list[object]:
    """Return a policy value as a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _has_github_provider(principal: object) -> bool:
    """Check whether a principal trusts the GitHub Actions OIDC provider."""
    if not isinstance(principal, dict):
        return False
    return any(
        str(provider).endswith(f"/{GITHUB_OIDC_HOST}")
        for provider in _as_list(principal.get("Federated"))
    )


def _has_web_identity_action(action: object) -> bool:
    """Match web identity actions case-insensitively, including wildcards."""
    target_action = WEB_IDENTITY_ACTION.casefold()
    return any(
        fnmatchcase(target_action, str(value).casefold()) for value in _as_list(action)
    )


def _subject_values(condition: object) -> tuple[list[object], bool]:
    """Return sub values using supported positive operators and case-insensitive keys."""
    if not isinstance(condition, dict):
        return [], False

    valid_operators = {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    }
    values = []
    valid_operator_seen = False
    for operator, entries in condition.items():
        if operator not in valid_operators or not isinstance(entries, dict):
            continue
        for key, value in entries.items():
            if str(key).casefold() == GITHUB_SUB_KEY.casefold():
                valid_operator_seen = True
                values.extend(_as_list(value))
    return values, valid_operator_seen


def _subject_is_restricted(
    values: Iterable[object], allowed_owners: Iterable[str] | None = None
) -> bool:
    """Validate each repository subject and apply an optional owner allowlist."""
    values = list(values)
    if not values:
        return False
    allowed_owners = {str(owner).casefold() for owner in allowed_owners or []}
    for value in values:
        if not isinstance(value, str) or not value.startswith("repo:"):
            return False
        parts = value[5:].split(":")
        owner_repo = parts[0].split("/", 1)
        if (
            len(owner_repo) != 2
            or not owner_repo[0]
            or not owner_repo[1]
            or (len(parts) > 1 and not parts[1])
        ):
            return False
        owner, repository = owner_repo
        if (
            "*" in owner
            or "?" in owner
            or (allowed_owners and owner.casefold() not in allowed_owners)
        ):
            return False
    return True


class iam_role_github_oidc_trust_subject_restricted(Check):
    """Ensure GitHub Actions OIDC trust policies restrict repository subjects."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate GitHub Actions OIDC trust policies for restricted subjects.

        Returns:
            A report for each IAM role trusting the GitHub Actions OIDC provider.
        """
        findings = []
        allowed_owners = (iam_client.audit_config or {}).get(
            "iam_github_oidc_allowed_owners", []
        )
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
                values, strict_operator_seen = _subject_values(
                    statement.get("Condition")
                )
                if not strict_operator_seen or not _subject_is_restricted(
                    values, allowed_owners
                ):
                    compliant = False
                    break

            report.status = "PASS" if compliant else "FAIL"
            if compliant:
                report.status_extended = f"IAM Role {role.name} restricts GitHub Actions OIDC trust to specific repository owners."
            else:
                report.status_extended = f"IAM Role {role.name} does not restrict GitHub Actions OIDC trust to allowed repository owners."
            findings.append(report)
        return findings
