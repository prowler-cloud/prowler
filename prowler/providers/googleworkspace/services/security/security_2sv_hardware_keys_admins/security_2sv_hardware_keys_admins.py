from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.lib.durations import (
    ONE_DAY_SECONDS,
    enforcement_issue,
    format_duration,
    parse_duration_seconds,
)
from prowler.providers.googleworkspace.services.security.lib.scope import (
    failures_shadowed_by_overrides,
    override_caveat,
    unevaluable_reason,
)
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)

# "Methods: Only security key". The values that also accept security codes are
# PASSKEY_PLUS_SECURITY_CODE and PASSKEY_PLUS_IP_BOUND_SECURITY_CODE, so
# requiring this one covers the benchmark's "don't allow users to generate
# security codes" step as well.
SECURITY_KEYS_ONLY = "PASSKEY_ONLY"

# The settings this check reads, to tell whether an override reaches it.
EVALUATED_SETTINGS = frozenset(
    {
        "security.two_step_verification_enrollment",
        "security.two_step_verification_enforcement",
        "security.two_step_verification_enforcement_factor",
        "security.two_step_verification_sign_in_code",
    }
)


class security_2sv_hardware_keys_admins(Check):
    """Check that 2SV enforcement requires hardware security keys.

    CIS 4.1.1.2 asks for security keys to be the only accepted method, with
    enrollment allowed, enforcement on or scheduled, and a policy suspension
    grace period of at most one day, so the requirement cannot pass on the
    accepted method alone.

    Note: the Cloud Identity Policy API returns domain-wide policies, it cannot
    verify enforcement for admin roles specifically. This check evaluates the
    customer-level policy, which applies to all users including administrators,
    so a passing domain-wide policy also covers the administrative accounts.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if security_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=security_client.policies,
                resource_id="securityPolicies",
                resource_name="Security Policies",
                customer_id=security_client.provider.identity.customer_id,
            )

            policies = security_client.policies
            domain = security_client.provider.identity.domain

            unevaluable = unevaluable_reason(policies, EVALUATED_SETTINGS)
            if unevaluable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"2-Step Verification could not be evaluated in domain "
                    f"{domain}: {unevaluable}. Review it in the Admin console."
                )
                findings.append(report)
                return findings

            caveat = override_caveat(policies, EVALUATED_SETTINGS)
            issues = []  # (setting, why it fails)

            factor_set = policies.two_sv_allowed_factor_set
            if factor_set != SECURITY_KEYS_ONLY:
                issues.append(
                    (
                        "security.two_step_verification_enforcement_factor",
                        "the accepted method is not configured and defaults to "
                        "any method, including SMS and phone call"
                        if factor_set is None
                        else f"the accepted method is {factor_set} "
                        f"(should be {SECURITY_KEYS_ONLY})",
                    )
                )

            # 4.1.1.2 accepts "On from <date>", unlike 4.1.1.1 and 4.1.1.3.
            enforcement = enforcement_issue(
                policies.two_sv_enforced_from, allow_scheduled=True
            )
            if enforcement:
                issues.append(
                    ("security.two_step_verification_enforcement", enforcement)
                )

            if policies.two_sv_allow_enrollment is False:
                issues.append(
                    (
                        "security.two_step_verification_enrollment",
                        "users are not allowed to turn on 2-Step Verification",
                    )
                )

            # Google's default is no suspension grace period, which is stricter
            # than the one day the benchmark asks for, so only longer periods
            # fail. A value Prowler cannot read fails closed.
            raw_grace_period = policies.two_sv_backup_code_exception_period
            grace_period = parse_duration_seconds(raw_grace_period)
            if raw_grace_period and grace_period is None:
                issues.append(
                    (
                        "security.two_step_verification_sign_in_code",
                        f"the 2-Step Verification policy suspension grace period "
                        f"'{raw_grace_period}' could not be read",
                    )
                )
            elif grace_period is not None and grace_period > ONE_DAY_SECONDS:
                issues.append(
                    (
                        "security.two_step_verification_sign_in_code",
                        f"the 2-Step Verification policy suspension grace period "
                        f"is {format_duration(raw_grace_period)} "
                        f"(should not exceed 1 day)",
                    )
                )

            failing_settings = frozenset(setting for setting, _ in issues)
            reasons = "; ".join(text for _, text in issues)

            if issues and failures_shadowed_by_overrides(policies, failing_settings):
                # The admin group of 4.1.1.2 may get the overriding value,
                # which the Policy API does not expose, so the domain-wide
                # failure cannot be confirmed for it.
                report.status = "MANUAL"
                report.status_extended = (
                    f"2-Step Verification does not require security keys in the "
                    f"domain-wide policy of {domain}: {reasons}. However, every "
                    f"failing setting is also overridden for at least one group "
                    f"or organizational unit, so the administrative accounts may "
                    f"be configured correctly. Review those overrides in the "
                    f"Admin console."
                )
            elif issues:
                report.status = "FAIL"
                report.status_extended = (
                    f"2-Step Verification does not require security keys as "
                    f"configured in domain {domain}: {reasons}. "
                    + (f"Note: {caveat}. " if caveat else "")
                    + "Note: this check evaluates the domain-wide policy, the "
                    "Policy API does not expose role-specific 2SV enforcement."
                )
            elif caveat:
                report.status = "MANUAL"
                report.status_extended = (
                    f"2-Step Verification meets the benchmark in the domain-wide "
                    f"policy of {domain}, but {caveat}. Review those overrides "
                    f"in the Admin console."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"2-Step Verification requires security keys only in domain "
                    f"{domain}, enforcement is on or scheduled and the policy "
                    f"suspension grace period is "
                    f"{format_duration(policies.two_sv_backup_code_exception_period)}. "
                    f"Note: this check evaluates the domain-wide policy, the "
                    f"Policy API does not expose role-specific 2SV enforcement."
                )

            findings.append(report)

        return findings
