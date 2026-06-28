from unittest.mock import MagicMock

from prowler.providers.linode.models import (
    LinodeIdentityInfo,
    LinodeSession,
)

# Linode Identity
USERNAME = "admin"
EMAIL = "admin@example.com"
ACCOUNT_ID = "E1AF1B6C-1111-2222-3333-444455556666"

# Linode Credentials
TOKEN = "fake-linode-token-for-testing"


def set_mocked_linode_provider(
    username: str = USERNAME,
    email: str = EMAIL,
    account_id: str = ACCOUNT_ID,
):
    """Return a mocked LinodeProvider with identity and session set."""
    provider = MagicMock()
    provider.type = "linode"
    provider.identity = LinodeIdentityInfo(
        username=username,
        email=email,
        account_id=account_id,
    )
    provider.session = LinodeSession(
        client=MagicMock(),
        token=TOKEN,
    )
    return provider
