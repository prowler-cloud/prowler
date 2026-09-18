from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from prowler.providers.snowflake.models import (
    SnowflakeIdentityInfo,
    SnowflakeSession,
)

# Snowflake Identity
ACCOUNT = "myorg-myaccount"
ACCOUNT_LOCATOR = "AB12345"
REGION = "AWS_EU_WEST_1"
USER = "PROWLER_SVC"
ROLE = "PROWLER_RO"
WAREHOUSE = "PROWLER_WH"


def generate_private_key_pem(passphrase: str = None) -> str:
    """Generate a throwaway RSA private key for tests.

    Generated per run rather than checked in, so no key material -- not even an unused
    test key -- lives in the repository.

    Args:
        passphrase: Optional passphrase to encrypt the key with.

    Returns:
        str: The PEM-encoded PKCS#8 private key.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode()


def set_mocked_snowflake_provider(
    account: str = ACCOUNT,
    account_locator: str = ACCOUNT_LOCATOR,
    region: str = REGION,
    user: str = USER,
    role: str = ROLE,
    warehouse: str = WAREHOUSE,
):
    """Return a mocked SnowflakeProvider with identity and session set."""
    provider = MagicMock()
    provider.type = "snowflake"
    provider.identity = SnowflakeIdentityInfo(
        account=account,
        account_locator=account_locator,
        region=region,
        user=user,
        role=role,
        warehouse=warehouse,
    )
    provider.session = SnowflakeSession(
        account=account,
        user=user,
        client=MagicMock(),
        role=role,
        warehouse=warehouse,
    )
    provider.audit_config = {}
    provider.fixer_config = {}
    return provider
