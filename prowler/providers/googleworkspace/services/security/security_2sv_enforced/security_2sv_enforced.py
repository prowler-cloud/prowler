from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.lib.durations import (
    TWO_WEEKS_SECONDS,
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

# "Methods: Any except verification codes via text, phone call". Listed as an
# allow list so a value Prowler does not know cannot pass by not being "ALL".
TELEPHONY_FREE_FACTOR_SETS = {
    "NO_TELEPHONY",
    "PASSKEY_ONLY",
    "PASSKEY_PLUS_SECURITY_CODE",
    "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE",
}

# The settings this check reads, to tell whether an override reaches it.
EVALUATED_SETTINGS = frozenset(
    {
        "security.two_step_verification_enrollment",
        "security.two_step_verification_enforcement",
        "security.two_step_verification_enforcement_factor",
        "security.two_step_verification_device_trust",
        "security.two_step_verification_grace_period",
    }
)


class security_2sv_enforced(Check):
    """Check that 2-Step Verification is enforced following the CIS audit steps.

    CIS 4.1.1.1 and 4.1.1.3 ask for more than enforcement being on: users must
    be allowed to turn 2-Step Verification on, the new user enrollment period
    must not exceed two weeks, device trust must be off and verification codes
    via text or phone call must not be an accepted method. Each of those is
    evaluated here so the requirement cannot pass on enforcement alone.

    Note: 4.1.1.1 audits the group holding every admin role, but the Cloud
    Identity Policy API returns domain-wide policies only. This check evaluates
    the customer-level policy, which applies to administrators too.
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

            enforced_from = policies.two_sv_enforced_from
            enforcement = enforcement_issue(enforced_from)
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

            # Google's default is no enrollment period, which is stricter than
            # the two weeks the benchmark asks for, so only longer periods fail.
            # A value Prowler cannot read fails closed rather than being skipped.
            raw_grace_period = policies.two_sv_enrollment_grace_period
            grace_period = parse_duration_seconds(raw_grace_period)
            if raw_grace_period and grace_period is None:
                issues.append(
                    (
                        "security.two_step_verification_grace_period",
                        f"the new user enrollment period '{raw_grace_period}' "
                        f"could not be read",
                    )
                )
            elif grace_period is not None and grace_period > TWO_WEEKS_SECONDS:
                issues.append(
                    (
                        "security.two_step_verification_grace_period",
                        f"the new user enrollment period is "
                        f"{format_duration(policies.two_sv_enrollment_grace_period)} "
                        f"(should not exceed 2 weeks)",
                    )
                )

            if policies.two_sv_allow_trusting_device is not False:
                issues.append(
                    (
                        "security.two_step_verification_device_trust",
                        "users are allowed to trust their device"
                        if policies.two_sv_allow_trusting_device
                        else "device trust is not configured and defaults to allowed",
                    )
                )

            factor_set = policies.two_sv_allowed_factor_set
            if factor_set not in TELEPHONY_FREE_FACTOR_SETS:
                issues.append(
                    (
                        "security.two_step_verification_enforcement_factor",
                        "the allowed methods are not configured and default to "
                        "any method, including verification codes via text and "
                        "phone call"
                        if factor_set is None
                        else f"the allowed methods are {factor_set}, which does "
                        f"not exclude verification codes via text and phone call",
                    )
                )

            failing_settings = frozenset(setting for setting, _ in issues)
            reasons = "; ".join(text for _, text in issues)

            if issues and failures_shadowed_by_overrides(policies, failing_settings):
                # The audited scope (e.g. the admin group of 4.1.1.1) may get
                # the overriding value, which the Policy API does not expose,
                # so the domain-wide failure cannot be confirmed for it.
                report.status = "MANUAL"
                report.status_extended = (
                    f"2-Step Verification is not enforced as required in the "
                    f"domain-wide policy of {domain}: {reasons}. However, every "
                    f"failing setting is also overridden for at least one group "
                    f"or organizational unit, so the audited scope may be "
                    f"configured correctly. Review those overrides in the Admin "
                    f"console."
                )
            elif issues:
                report.status = "FAIL"
                report.status_extended = (
                    f"2-Step Verification is not enforced as required in domain "
                    f"{domain}: {reasons}."
                    + (f" Note: {caveat}." if caveat else "")
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
                    f"2-Step Verification is enforced in domain {domain} "
                    f"(enforced from {enforced_from}), device trust is disabled "
                    f"and verification codes via text or phone call are not an "
                    f"accepted method."
                )

            findings.append(report)

        return findings
