from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.password_policy_helpers import (
    active_password_policies,
    missing_password_policies_scope_finding,
    no_active_password_policies_finding,
    password_policy_label,
)


class authenticator_password_lockout_threshold_3(Check):
    """STIG V-273189 / OKTA-APP-000170.

    Every active Okta Password Policy must lock accounts after no more than 3 consecutive failed login attempts.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        findings = []
        org_domain = authenticator_client.provider.identity.org_domain
        requirement = "password lockout after 3 or fewer failed attempts"
        missing_scope = authenticator_client.missing_scope.get("password_policies")

        if missing_scope:
            return [
                missing_password_policies_scope_finding(
                    self.metadata(), org_domain, missing_scope, requirement
                )
            ]

        policies = active_password_policies(authenticator_client.password_policies)
        if not policies:
            return [
                no_active_password_policies_finding(
                    self.metadata(), org_domain, requirement
                )
            ]

        for policy in policies:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=policy, org_domain=org_domain
            )
            if policy.max_attempts is not None and policy.max_attempts <= 3:
                report.status = "PASS"
                report.status_extended = (
                    f"{password_policy_label(policy)} enforces {requirement} "
                    f"(maximum failed attempts: {policy.max_attempts})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{password_policy_label(policy)} does not enforce {requirement} "
                    f"(maximum failed attempts: {policy.max_attempts})."
                )
            findings.append(report)
        return findings
