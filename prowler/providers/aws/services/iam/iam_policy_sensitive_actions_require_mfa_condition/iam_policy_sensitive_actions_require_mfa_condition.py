from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    get_effective_actions,
    has_mfa_condition,
)

# Actions capable of privilege escalation or credential creation, where
# requiring MFA at the point of use is a meaningful defense-in-depth control
# even when the calling principal already has MFA enabled on their account.
SENSITIVE_ACTIONS = {
    "iam:createaccesskey",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:passrole",
    "sts:assumerole",
}


class iam_policy_sensitive_actions_require_mfa_condition(Check):
    """Check that customer-managed IAM policies require MFA for sensitive actions.

    Flags statements that grant sensitive, escalation-capable actions
    (see SENSITIVE_ACTIONS) — including via wildcards like `iam:*` or a
    `NotAction` clause — without a Condition block requiring
    aws:MultiFactorAuthPresent.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check against every customer-managed IAM policy.

        Returns:
            list[Check_Report_AWS]: One report per customer-managed policy,
                FAIL if any statement grants a sensitive action without an
                MFA condition, PASS otherwise.
        """
        findings = []

        for policy in iam_client.policies.values():
            if policy.type == "Custom":
                if not policy.attached and not iam_client.provider.scan_unused_services:
                    continue

                report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
                report.region = iam_client.region
                report.status = "PASS"
                report.status_extended = f"Custom Policy {report.resource_arn} does not allow sensitive actions without requiring MFA."

                statements = (
                    policy.document.get("Statement", []) if policy.document else []
                )
                if not isinstance(statements, list):
                    statements = [statements]

                unprotected_actions = set()
                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    # Wrapping the single statement lets get_effective_actions
                    # expand wildcards (e.g. iam:*) and NotAction clauses for
                    # just this statement, using the same logic already
                    # relied on elsewhere in this file.
                    effective_actions = {
                        action.lower()
                        for action in get_effective_actions({"Statement": [statement]})
                    }

                    matched_actions = effective_actions & SENSITIVE_ACTIONS
                    if matched_actions and not has_mfa_condition(statement):
                        unprotected_actions.update(matched_actions)

                if unprotected_actions:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Custom Policy {report.resource_arn} allows the following sensitive actions without requiring MFA: "
                        + ", ".join(
                            f"'{action}'" for action in sorted(unprotected_actions)
                        )
                        + "."
                    )

                findings.append(report)

        return findings
