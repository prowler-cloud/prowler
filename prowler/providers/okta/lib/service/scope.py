from pydantic import BaseModel

from prowler.lib.check.models import CheckReportOkta


class MissingScopeResource(BaseModel):
    """Synthetic resource used when a check cannot evaluate an Okta API."""

    id: str
    name: str


def missing_scope_finding(
    *,
    metadata,
    org_domain: str,
    resource_id: str,
    resource_name: str,
    missing_scopes: list[str],
    action: str,
) -> CheckReportOkta:
    """Build a MANUAL finding for checks blocked by missing OAuth scopes."""
    resource = MissingScopeResource(id=resource_id, name=resource_name)
    report = CheckReportOkta(
        metadata=metadata,
        resource=resource,
        org_domain=org_domain,
        resource_id=resource.id,
        resource_name=resource.name,
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Prowler could not {action} because the Okta service app is missing "
        f"required OAuth scope(s): {', '.join(missing_scopes)}. Grant the "
        "scope(s) to the service app and rerun the check, or review the "
        "configuration manually in the Okta Admin Console."
    )
    return report
