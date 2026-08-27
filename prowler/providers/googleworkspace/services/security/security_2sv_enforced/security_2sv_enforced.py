from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.security.lib.durations import (
    TWO_WEEKS_SECONDS,
    format_duration,
    is_enforcement_active,
    is_enforcement_off,
    parse_duration_seconds,
)
from prowler.providers.googleworkspace.services.security.security_client import (
    security_client,
)

# "Methods: Any" allows verification codes via text and phone call, which the
# benchmark excludes. Every other value of the enum (NO_TELEPHONY,
# PASSKEY_ONLY, PASSKEY_PLUS_SECURITY_CODE, PASSKEY_PLUS_IP_BOUND_SECURITY_CODE)
# rules telephony out.
ALL_SIGN_IN_FACTORS = "ALL"


class security_2sv_enforced(Check):
    """Check that 2-Step Verification is enforced following the CIS audit steps.

    CIS 4.1.1.1 and 4.1.1.3 ask for more than enforcement being on: users must
    be allowed to turn 2-Step Verification on, the new user enrollment period
    must not exceed two weeks, device trust must be off and verification codes
    via text or phone call must not be an accepted method. Each of those is
    evaluated here so the requirement cannot pass on enforcement alone.
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
            issues = []

            enforced_from = policies.two_sv_enforced_from
            if is_enforcement_off(enforced_from):
                issues.append(
                    "enforcement is not configured and defaults to OFF"
                    if enforced_from is None
                    else "enforcement is set to OFF"
                )
            elif not is_enforcement_active(enforced_from):
                # "On from <future date>" means nobody is enforced yet.
                issues.append(f"enforcement does not start until {enforced_from}")

            if policies.two_sv_allow_enrollment is False:
                issues.append("users are not allowed to turn on 2-Step Verification")

            # Google's default is no enrollment period, which is stricter than
            # the two weeks the benchmark asks for, so only longer periods fail.
            # A value Prowler cannot read fails closed rather than being skipped.
            raw_grace_period = policies.two_sv_enrollment_grace_period
            grace_period = parse_duration_seconds(raw_grace_period)
            if raw_grace_period and grace_period is None:
                issues.append(
                    f"the new user enrollment period '{raw_grace_period}' "
                    f"could not be read"
                )
            elif grace_period is not None and grace_period > TWO_WEEKS_SECONDS:
                issues.append(
                    f"the new user enrollment period is "
                    f"{format_duration(policies.two_sv_enrollment_grace_period)} "
                    f"(should not exceed 2 weeks)"
                )

            if policies.two_sv_allow_trusting_device is not False:
                issues.append(
                    "users are allowed to trust their device"
                    if policies.two_sv_allow_trusting_device
                    else "device trust is not configured and defaults to allowed"
                )

            factor_set = policies.two_sv_allowed_factor_set
            if factor_set is None or factor_set == ALL_SIGN_IN_FACTORS:
                issues.append(
                    "the allowed methods are not configured and default to any method, "
                    "including verification codes via text and phone call"
                    if factor_set is None
                    else "any method is allowed, including verification codes via "
                    "text and phone call"
                )

            if not issues:
                report.status = "PASS"
                report.status_extended = (
                    f"2-Step Verification is enforced in domain {domain} "
                    f"(enforced from {enforced_from}), device trust is disabled "
                    f"and verification codes via text or phone call are not an "
                    f"accepted method."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"2-Step Verification is not enforced as required in domain "
                    f"{domain}: {'; '.join(issues)}."
                )

            findings.append(report)

        return findings
