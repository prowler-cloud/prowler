"""Obviously-fake credentials for tests.

Deliberately unrealistic so repository secret scanning does not flag them. Never
put a value here that could be mistaken for a real key.
"""

import base64
import json
import time

# Prowler API keys are recognised by their `pk_` prefix; anything else is rejected.
FAKE_API_KEY = "pk_fake_api_key_for_unit_testing_only"
FAKE_LEGACY_API_KEY = "pk_fake_legacy_api_key_for_unit_testing_only"
MALFORMED_API_KEY = "not_a_prowler_api_key"


def fake_jwt(expires_in: int = 3600, **claims: object) -> str:
    """Mint an unsigned JWT whose ``exp`` is ``expires_in`` seconds from now.

    Pass a negative ``expires_in`` for an already-expired token.

    ``ProwlerAppAuth._parse_jwt`` only base64url-decodes the payload and reads
    ``exp`` -- it never verifies the signature, because the Prowler API is what
    validates the token. A placeholder signature is therefore enough, and avoids
    adding a JWT library just for tests.
    """

    def _segment(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = _segment({"alg": "HS256", "typ": "JWT"})
    body = _segment({"exp": int(time.time()) + expires_in, **claims})
    return f"{header}.{body}.fake-signature-not-verified"
