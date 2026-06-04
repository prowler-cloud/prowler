from prowler.providers.okta.services.authenticator.authenticator_service import (
    AuthenticatorSummary,
    OktaAuthenticator,
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
