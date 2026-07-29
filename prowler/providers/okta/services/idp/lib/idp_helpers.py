"""Shared helpers for the OKTA idp STIG checks."""

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.idp.idp_service import OktaIdentityProvider


def missing_idps_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding when the IdPs scope is not granted."""
    placeholder = OktaIdentityProvider(
        id="okta-idps-scope-missing",
        name="(scope not granted)",
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        "Could not retrieve Okta Identity Providers: the Okta service app is "
        f"missing the required `{scope}` API scope. Grant it on the service "
        "app's Okta API Scopes tab in the Okta Admin Console, then re-run the "
        "check."
    )
    return report
