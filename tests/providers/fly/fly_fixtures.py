from unittest.mock import MagicMock

from prowler.providers.fly.models import (
    FlyIdentityInfo,
    FlyOrganization,
    FlySession,
)

# Fly.io Identity
ORG_ID = "org_test123"
ORG_SLUG = "test-org"
ORG_NAME = "Test Org"

# Fly.io Credentials
API_TOKEN = "test-fly-api-token"

# App Constants
APP_ID = "app_test456"
APP_NAME = "test-app"

# Machine Constants
MACHINE_ID = "148e21eb1de389"
MACHINE_NAME = "test-machine"
REGION = "fra"

# Volume Constants
VOLUME_ID = "vol_test789"
VOLUME_NAME = "test_volume"


def set_mocked_fly_provider(
    api_token: str = API_TOKEN,
    org_slug: str = ORG_SLUG,
    identity: FlyIdentityInfo = None,
    audit_config: dict = None,
):
    """Create a mocked FlyProvider for testing.

    Args:
        api_token: Fly.io API token of the mocked session.
        org_slug: Organization slug the mocked scan is scoped to.
        identity: Override for the provider identity.
        audit_config: Override for the provider audit configuration.

    Returns:
        MagicMock: A mocked Fly.io provider.
    """
    provider = MagicMock()
    provider.type = "fly"
    provider.session = FlySession(
        token=api_token,
        org_slug=org_slug,
        http_session=MagicMock(),
    )
    organization = FlyOrganization(id=ORG_ID, slug=org_slug, name=ORG_NAME)
    provider.identity = identity or FlyIdentityInfo(
        organization=organization,
        organizations=[organization],
    )
    provider.audit_config = audit_config or {}
    provider.fixer_config = {}
    provider.filter_apps = None

    return provider
