from copy import deepcopy

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.ses.ses_client import ses_client


def _normalize_policy_statements(policy: dict) -> dict:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return {**policy, "Statement": [statements]}
    return policy


def _has_explicit_deny(policy: dict) -> bool:
    return any(
        isinstance(statement, dict) and statement.get("Effect") == "Deny"
        for statement in _normalize_policy_statements(policy).get("Statement", [])
    )


class ses_identity_not_publicly_accessible(Check):
    """Ensure SES identities are not publicly accessible through authorization policies."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate every authorization policy attached to each SES identity.

        Returns:
            A list of reports containing the public-access result for each identity.
        """
        findings = []
        for identity in ses_client.email_identities.values():
            if not identity.policies:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=identity)
            report.status = "PASS"
            report.status_extended = (
                f"SES identity {identity.name} is not publicly accessible."
            )
            has_public_allow = any(
                is_policy_public(
                    _normalize_policy_statements(deepcopy(policy)),
                    ses_client.audited_account,
                )
                for policy in identity.policies.values()
            )
            if has_public_allow:
                if any(
                    _has_explicit_deny(policy) for policy in identity.policies.values()
                ):
                    report.status = "MANUAL"
                    report.status_extended = f"SES identity {identity.name} has public Allow and explicit Deny statements in its resource policies. Effective public access requires manual review."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SES identity {identity.name} is publicly accessible due to its resource policies."

            findings.append(report)

        return findings
