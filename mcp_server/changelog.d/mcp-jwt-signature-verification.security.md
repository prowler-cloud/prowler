JWT signatures in HTTP transport mode are verified against the Prowler API RS256 public key when `DJANGO_TOKEN_VERIFYING_KEY` is set, refusing forged, `alg: none` and HMAC-keyed tokens
