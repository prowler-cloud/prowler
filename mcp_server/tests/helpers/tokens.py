"""Obviously-fake credentials for tests.

Deliberately unrealistic so repository secret scanning does not flag them. Never
put a value here that could be mistaken for a real key. The RSA key pairs below
are generated fresh on every import and never leave the test process.
"""

import base64
import hashlib
import hmac
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Prowler API keys are recognised by their `pk_` prefix; anything else is rejected.
FAKE_API_KEY = "pk_fake_api_key_for_unit_testing_only"
FAKE_LEGACY_API_KEY = "pk_fake_legacy_api_key_for_unit_testing_only"
MALFORMED_API_KEY = "not_a_prowler_api_key"


def _generate_rsa_pem_pair() -> tuple[str, str]:
    """Return a (private, public) PEM pair shaped like the API's generated keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


# The pair the MCP server under test trusts, and an unrelated pair an attacker
# could hold. Module-level so the 2048-bit generation runs once per session.
JWT_SIGNING_KEY, JWT_VERIFYING_KEY = _generate_rsa_pem_pair()
ROGUE_JWT_SIGNING_KEY, _ = _generate_rsa_pem_pair()


def _jwt_payload(expires_in: int, claims: dict[str, object]) -> dict[str, object]:
    """The claim set the Prowler API issues, so the verifier sees a realistic token."""
    now = int(time.time())
    return {
        "typ": "access",
        "iss": "https://api.testing.invalid",
        "aud": "https://api.testing.invalid",
        "iat": now,
        "exp": now + expires_in,
        "jti": "0f0f0f0f0f0f4f0f8f0f0f0f0f0f0f0f",
        "sub": "00000000-0000-4000-8000-000000000000",
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        **claims,
    }


def fake_jwt(
    expires_in: int = 3600,
    *,
    signing_key: str = JWT_SIGNING_KEY,
    **claims: object,
) -> str:
    """Mint an RS256 JWT whose ``exp`` is ``expires_in`` seconds from now.

    Pass a negative ``expires_in`` for an already-expired token, or
    ``signing_key=ROGUE_JWT_SIGNING_KEY`` for one the server must not trust.
    """
    return jwt.encode(_jwt_payload(expires_in, claims), signing_key, algorithm="RS256")


def unsigned_jwt(expires_in: int = 3600, **claims: object) -> str:
    """Mint a JWT declaring ``alg: none`` with an empty signature segment."""
    return jwt.encode(_jwt_payload(expires_in, claims), key=None, algorithm="none")


def hmac_jwt_keyed_with(secret: str, expires_in: int = 3600, **claims: object) -> str:
    """Mint an HS256 JWT keyed with ``secret``, e.g. the server's public key.

    Built by hand because ``jwt.encode`` refuses a PEM as an HMAC secret, which
    is exactly the algorithm-confusion token the server must refuse too.
    """

    def _segment(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = _segment(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _segment(json.dumps(_jwt_payload(expires_in, claims)).encode())
    signature = hmac.new(
        secret.encode(), f"{header}.{body}".encode(), hashlib.sha256
    ).digest()
    return f"{header}.{body}.{_segment(signature)}"
