from prowler.providers.okta.services.apitoken.api_token_service import OktaApiToken

ANYWHERE_CONNECTIONS = {"", "ANYWHERE", "ANY_IP"}


def network_zone_restriction_status(
    token: OktaApiToken, known_network_zone_ids: set[str]
) -> tuple[str, str]:
    """Evaluate whether an API token is restricted to known Network Zones."""
    connection = token.network_connection.upper()
    if connection in ANYWHERE_CONNECTIONS:
        return (
            "FAIL",
            f"API token '{token.name}' can be used from any IP address. "
            "Restrict the token to one or more known Okta Network Zones.",
        )

    referenced_zones = token.network_includes + token.network_excludes
    if not referenced_zones:
        return (
            "FAIL",
            f"API token '{token.name}' is not open to Any IP, but it does not "
            "reference a specific Okta Network Zone.",
        )

    unknown_zones = [
        zone for zone in referenced_zones if zone not in known_network_zone_ids
    ]
    if unknown_zones:
        return (
            "FAIL",
            f"API token '{token.name}' references unknown Network Zone(s): "
            f"{', '.join(unknown_zones)}.",
        )

    return (
        "PASS",
        f"API token '{token.name}' is restricted to known Okta Network Zone(s): "
        f"{', '.join(referenced_zones)}.",
    )


def owner_has_super_admin(token: OktaApiToken) -> bool:
    """Return True when any token owner role is Super Admin."""
    for role in token.owner_roles:
        normalized = role.strip().replace(" ", "_").upper()
        if normalized in {"SUPER_ADMIN", "SUPER_ADMINISTRATOR"}:
            return True
    return False
