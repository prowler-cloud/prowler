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


class authenticator_password_minimum_age_24h(Check):
    """STIG V-273200 / OKTA-APP-000740.

    Every active Okta Password Policy must enforce a 24-hour minimum password age.
    The check emits one finding per active policy so a weaker
    custom policy cannot hide behind a compliant default.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate all active Okta Password Policies."""
        findings = []
        org_domain = authenticator_client.provider.identity.org_domain
        requirement = "minimum password age of at least 24 hours"
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
            if policy.min_age_minutes is not None and policy.min_age_minutes >= 1440:
                report.status = "PASS"
                report.status_extended = (
                    f"{password_policy_label(policy)} enforces {requirement} "
                    f"(minimum age minutes: {policy.min_age_minutes})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{password_policy_label(policy)} does not enforce {requirement} "
                    f"(minimum age minutes: {policy.min_age_minutes})."
                )
            findings.append(report)
        return findings
