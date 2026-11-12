from prowler.providers.cloudflare.services.account.account_service import (
    CloudflareAPIToken,
)
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID

TOKEN_ID = "token-1"
TOKEN_NAME = "ci-token"


def make_token(**kwargs):
    defaults = dict(
        id=TOKEN_ID,
        name=TOKEN_NAME,
        owner="account",
        account_id=ACCOUNT_ID,
        status="active",
    )
    defaults.update(kwargs)
    return CloudflareAPIToken(**defaults)
