from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.apitoken.api_token_service import OktaApiToken

ANYWHERE_CONNECTIONS = {"", "ANYWHERE", "ANY_IP"}
_SCOPE_ADVICE = (
    "Grant it on the Okta API Scopes tab of the service app in the Okta Admin "
    "Console, then re-run the check."
)


def network_zone_restriction_status(
    token: OktaApiToken, known_network_zone_ids: set[str]
) -> tuple[str, str]:
    """Evaluate whether an API token is restricted to known Network Zones."""
    connection = token.network_connection.upper()
    if connection in ANYWHERE_CONNECTIONS:
        return (
            "FAIL",
            f"API token {token.name} can be used from any IP address. "
            "Restrict the token to one or more known Okta Network Zones.",
        )

    if not token.network_includes:
        return (
            "FAIL",
            f"API token {token.name} does not allowlist a specific Okta "
            "Network Zone. Excluded zones do not restrict the token to trusted "
            "source networks.",
        )

    unknown_zones = [
        zone for zone in token.network_includes if zone not in known_network_zone_ids
    ]
    if unknown_zones:
        return (
            "FAIL",
            f"API token {token.name} references unknown Network Zone(s): "
            f"{', '.join(unknown_zones)}.",
        )

    return (
        "PASS",
        f"API token {token.name} is restricted to known Okta Network Zone(s): "
        f"{', '.join(token.network_includes)}.",
    )


def definite_network_zone_restriction_failure(
    token: OktaApiToken,
) -> tuple[str, str] | None:
    """Return a definite network restriction failure that does not need zone lookup."""
    connection = token.network_connection.upper()
    if connection in ANYWHERE_CONNECTIONS or not token.network_includes:
        return network_zone_restriction_status(token, set())
    return None


def owner_has_super_admin(token: OktaApiToken) -> bool:
    """Return True when any token owner role is Super Admin."""
    for role in token.owner_roles:
        normalized = role.strip().replace(" ", "_").upper()
        if normalized in {"SUPER_ADMIN", "SUPER_ADMINISTRATOR"}:
            return True
    return False


def missing_api_token_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when API tokens cannot be listed."""
    resource = OktaApiToken(
        id="api-tokens-scope-missing",
        name="(scope not granted)",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=resource, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve Okta API token metadata: the Okta service app "
        f"is missing the required `{scope}` API scope. {_SCOPE_ADVICE}"
    )
    return report


def missing_network_zone_scope_for_token_finding(
    metadata, org_domain: str, token: OktaApiToken, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when token zones cannot be validated."""
    report = CheckReportOkta(metadata=metadata, resource=token, org_domain=org_domain)
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not validate Network Zone restrictions for API token "
        f"{token.name}: the Okta service app is missing the required "
        f"`{scope}` API scope. {_SCOPE_ADVICE}"
    )
    return report


def missing_user_roles_scope_for_token_finding(
    metadata, org_domain: str, token: OktaApiToken, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when token owner roles cannot be listed."""
    report = CheckReportOkta(metadata=metadata, resource=token, org_domain=org_domain)
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve admin roles for API token {token.name} owner "
        f"{token.user_id}: the Okta service app is missing the required "
        f"`{scope}` API scope. {_SCOPE_ADVICE}"
    )
    return report
