"""Shared helpers for the OKTA systemlog STIG checks."""

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.systemlog.systemlog_service import LogStream


def missing_log_streams_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding when the log-streams scope is not granted."""
    placeholder = LogStream(
        id="okta-log-streams-scope-missing",
        name="(scope not granted)",
        status="MISSING",
        type="",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        "Could not retrieve Okta Log Streams: the Okta service app is missing "
        f"the required `{scope}` API scope. Grant it on the service app's "
        "Okta API Scopes tab in the Okta Admin Console, then re-run the check."
    )
    return report
