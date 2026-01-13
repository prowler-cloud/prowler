from unittest.mock import MagicMock

from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
from prowler.providers.cloudflare.models import (
    CloudflareAccount,
    CloudflareIdentityInfo,
    CloudflareSession,
)

# Cloudflare Identity
ACCOUNT_ID = "test-account-id"
ACCOUNT_NAME = "Test Account"
USER_ID = "test-user-id"
USER_EMAIL = "test@example.com"

# Cloudflare Credentials
API_TOKEN = "test-api-token"
API_KEY = "test-api-key"
API_EMAIL = "test@example.com"

# Zone Constants
ZONE_ID = "test-zone-id"
ZONE_NAME = "example.com"


def set_mocked_cloudflare_provider(
    api_token: str = API_TOKEN,
    identity: CloudflareIdentityInfo = None,
    audit_config: dict = None,
) -> CloudflareProvider:
    """Create a mocked CloudflareProvider for testing."""
    provider = MagicMock()
    provider.type = "cloudflare"
    provider.session = CloudflareSession(
        client=MagicMock(),
        api_token=api_token,
        api_key=None,
        api_email=None,
    )
    provider.identity = identity or CloudflareIdentityInfo(
        user_id=USER_ID,
        email=USER_EMAIL,
        accounts=[
            CloudflareAccount(
                id=ACCOUNT_ID,
                name=ACCOUNT_NAME,
                type="standard",
            )
        ],
        audited_accounts=[ACCOUNT_ID],
    )
    provider.audit_config = audit_config or {"max_retries": 3, "min_tls_version": "1.2"}
    provider.fixer_config = {}
    provider.filter_zones = None

    return provider
