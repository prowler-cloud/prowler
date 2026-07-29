"""Shared helpers for the OKTA user STIG checks."""

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.user.user_service import UserAutomation


def missing_user_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding when an OAuth scope is not granted."""
    placeholder = UserAutomation(
        id="okta-user-scope-missing",
        name="(scope not granted)",
        status="MISSING",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve Okta user lifecycle automations: the Okta service "
        f"app is missing the required `{scope}` API scope. Grant it on the "
        "service app's Okta API Scopes tab in the Okta Admin Console, then "
        "re-run the check."
    )
    return report
