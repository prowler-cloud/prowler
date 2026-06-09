from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_client import (
    authenticator_client,
)
from prowler.providers.okta.services.authenticator.lib.authenticator_helpers import (
    find_authenticator_by_key,
    missing_authenticator_resource,
    missing_authenticators_scope_finding,
)


class authenticator_okta_verify_fips_compliant(Check):
    """STIG V-273205 / OKTA-APP-001700.

    The check requires Okta to restrict Okta Verify enrollment to FIPS-compliant devices.
    """

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate Okta Verify FIPS compliance settings."""
        org_domain = authenticator_client.provider.identity.org_domain
        missing_scope = authenticator_client.missing_scope.get("authenticators")
        if missing_scope:
            return [
                missing_authenticators_scope_finding(
                    self.metadata(),
                    org_domain,
                    "okta_verify",
                    "Okta Verify authenticator",
                    missing_scope,
                )
            ]

        authenticator = find_authenticator_by_key(
            authenticator_client.authenticators, "okta_verify"
        )
        resource = authenticator or missing_authenticator_resource(
            "okta_verify", "Okta Verify authenticator"
        )
        report = CheckReportOkta(
            metadata=self.metadata(), resource=resource, org_domain=org_domain
        )
        if not authenticator:
            report.status = "FAIL"
            report.status_extended = "Okta Verify authenticator is missing."
        elif authenticator.status.upper() != "ACTIVE":
            report.status = "FAIL"
            report.status_extended = (
                f"Okta Verify authenticator is not active; current status is "
                f"{authenticator.status}."
            )
        elif authenticator.fips.upper() == "REQUIRED":
            report.status = "PASS"
            report.status_extended = (
                "Okta Verify authenticator requires FIPS-compliant devices "
                "for enrollment."
            )
        else:
            current_fips = authenticator.fips or "unset"
            report.status = "FAIL"
            report.status_extended = (
                "Okta Verify authenticator is active but does not require "
                "FIPS-compliant devices for enrollment (current value: "
                f"{current_fips})."
            )
        return [report]
