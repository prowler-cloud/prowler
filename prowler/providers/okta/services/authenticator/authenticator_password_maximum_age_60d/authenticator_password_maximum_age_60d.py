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


class authenticator_password_maximum_age_60d(Check):
    """STIG V-273201 / OKTA-APP-000745.

    Every active Okta Password Policy must enforce a 60-day maximum password age.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        findings = []
        org_domain = authenticator_client.provider.identity.org_domain
        requirement = "maximum password age of 60 days or less"
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
            if policy.max_age_days is not None and 0 < policy.max_age_days <= 60:
                report.status = "PASS"
                report.status_extended = (
                    f"{password_policy_label(policy)} enforces {requirement} "
                    f"(maximum age days: {policy.max_age_days})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{password_policy_label(policy)} does not enforce {requirement} "
                    f"(maximum age days: {policy.max_age_days})."
                )
            findings.append(report)
        return findings
