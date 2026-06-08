from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.authenticator.authenticator_service import (
    AuthenticatorSummary,
    OktaAuthenticator,
)

_SCOPE_ADVICE = (
    "Grant it on the Okta API Scopes tab of the service app in the Okta Admin "
    "Console, then re-run the check."
)


def find_authenticator_by_key(
    authenticators: dict[str, OktaAuthenticator], key: str
) -> OktaAuthenticator | None:
    """Return the first authenticator with the requested key."""
    for authenticator in authenticators.values():
        if authenticator.key == key:
            return authenticator
    return None


def missing_authenticator_resource(key: str, name: str) -> AuthenticatorSummary:
    """Build a synthetic resource for a missing authenticator."""
    return AuthenticatorSummary(id=f"{key}-missing", name=name)


def missing_authenticators_scope_finding(
    metadata, org_domain: str, key: str, name: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when authenticators cannot be listed."""
    resource = AuthenticatorSummary(id=f"{key}-scope-missing", name=name)
    report = CheckReportOkta(
        metadata=metadata, resource=resource, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve Okta authenticators to evaluate {name}: the Okta "
        f"service app is missing the required `{scope}` API scope. "
        f"{_SCOPE_ADVICE}"
    )
    return report
