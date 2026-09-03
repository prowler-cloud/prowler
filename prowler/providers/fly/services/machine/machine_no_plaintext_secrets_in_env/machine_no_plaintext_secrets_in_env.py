import re
from typing import Iterable, List
from urllib.parse import unquote, urlsplit

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.lib.service.service import config_value
from prowler.providers.fly.services.machine.machine_client import machine_client

DEFAULT_SECRET_NAME_PATTERNS = [
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "PASSPHRASE",
]

CREDENTIAL_QUERY_PARAMETERS = [
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "credential",
    "jwt",
    "key",
    "pass",
    "passwd",
    "password",
    "pwd",
    "secret",
    "session",
    "sessionid",
    "sig",
    "signature",
    "token",
]

# Path segments and parameter values at least this long made of opaque
# characters (base64, base64url and hex included) are treated as an embedded
# credential unless they are a UUID (an identifier, not a secret).
SECRET_LIKE_SEGMENT_MIN_LENGTH = 20
OPAQUE_SEGMENT = re.compile(r"[A-Za-z0-9_.~%=+/-]+")
OPAQUE_PART_SEPARATORS = re.compile(r"[-_.]")
UUID_SEGMENT = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
# API version segments such as "v1", "v2.1" or "2024-01-01" are route words.
VERSION_SEGMENT = re.compile(r"v?\d+([.-]\d+)*", re.IGNORECASE)


def is_credential_name(name: str, patterns: Iterable[str]) -> bool:
    """Return whether a parameter or path segment name denotes a credential.

    The name is normalized (``x-api-key`` -> ``x_api_key``) and split into
    words, so any word that is a known credential parameter, or any name that
    contains a secret-like pattern, counts as a credential.

    Args:
        name: The query parameter name or path segment.
        patterns: Secret-like substrings, matched case-insensitively.

    Returns:
        bool: True for a known credential parameter or a secret-like name.
    """
    normalized = name.lower().replace("-", "_")
    words = [word for word in normalized.split("_") if word]
    if normalized in CREDENTIAL_QUERY_PARAMETERS or any(
        word in CREDENTIAL_QUERY_PARAMETERS for word in words
    ):
        return True
    return any(pattern.lower() in normalized for pattern in patterns)


def _is_opaque_part(part: str) -> bool:
    """Return whether one separator-free part has the shape of a token.

    Slugs and versions are made of plain words and numbers separated by ``-``,
    ``_`` or ``.``; tokens mix letters with digits, mix letter cases, or use
    base64 characters within a single part.

    Args:
        part: A run of characters without ``-``, ``_`` or ``.``.

    Returns:
        bool: True when the part looks like part of a token.
    """
    has_digit = any(char.isdigit() for char in part)
    has_alpha = any(char.isalpha() for char in part)
    mixed_case = any(char.islower() for char in part) and any(
        char.isupper() for char in part
    )
    if has_digit and has_alpha and len(part) >= 8:
        return True
    if mixed_case and len(part) >= 16:
        return True
    return ("+" in part or "/" in part) and len(part) >= 16


def looks_like_secret(segment: str) -> bool:
    """Return whether a path segment or parameter value looks like a credential.

    A long run of opaque characters whose parts mix letters with digits, mix
    letter cases, or use base64 characters is the shape of tokens embedded in
    webhook URLs, signed URLs and bearer credentials. UUIDs, slugs such as
    ``contoso-prod-eu-west-1`` and versions are not treated as secrets.

    Args:
        segment: One path segment or parameter value, already URL-decoded.

    Returns:
        bool: True when the value looks like an embedded credential.
    """
    if len(segment) < SECRET_LIKE_SEGMENT_MIN_LENGTH:
        return False
    if UUID_SEGMENT.fullmatch(segment) or not OPAQUE_SEGMENT.fullmatch(segment):
        return False
    parts = [part for part in OPAQUE_PART_SEPARATORS.split(segment) if part]
    return any(_is_opaque_part(part) for part in parts)


def looks_like_value(segment: str) -> bool:
    """Return whether a path segment looks like a value rather than a route word.

    Args:
        segment: The path segment that follows a secret-like segment.

    Returns:
        bool: True for anything but a plain route word or an API version.
    """
    if VERSION_SEGMENT.fullmatch(segment):
        return False
    return (
        any(char.isdigit() for char in segment)
        or "=" in segment
        or ":" in segment
        or len(segment) >= 12
    )


def _split_parameters(component: str) -> list[tuple[str, str]]:
    """Split a query or fragment into decoded ``(name, value)`` pairs.

    ``parse_qs`` would decode ``+`` to a space, which hides base64 tokens, so
    the raw pairs are split here and decoded with ``unquote`` only.

    Args:
        component: The raw query or fragment string.

    Returns:
        list[tuple[str, str]]: The decoded name/value pairs, in order.
    """
    pairs = []
    for pair in re.split(r"[&;]", component):
        if not pair:
            continue
        name, _, value = pair.partition("=")
        pairs.append((unquote(name), unquote(value)))
    return pairs


def carries_credential_parameter(component: str, patterns: Iterable[str]) -> bool:
    """Return whether a query or fragment component carries a credential.

    Every parameter is inspected on its own: a credential-like name, an opaque
    token as name (a bare token such as ``#eyJ...``) or as value, or a nested
    URL that itself carries a credential marks the component.

    Args:
        component: The raw query or fragment string.
        patterns: Secret-like name substrings, matched case-insensitively.

    Returns:
        bool: True when the component carries a credential.
    """
    for name, value in _split_parameters(component):
        if is_credential_name(name, patterns) or looks_like_secret(name):
            return True
        if looks_like_secret(value):
            return True
        nested = urlsplit(value)
        if nested.netloc and (nested.username or nested.password):
            return True
        if nested.scheme in ("http", "https") and nested.netloc:
            if not is_credential_free_url(value, patterns):
                return True
    return False


def is_credential_free_url(
    value: str, patterns: Iterable[str] = DEFAULT_SECRET_NAME_PATTERNS
) -> bool:
    """Return whether a value is a bare endpoint URL that carries no credential.

    Names such as ``TOKEN_ISSUER_URL`` match the secret-like name patterns while
    holding a plain endpoint, so the value decides. A URL is credential-free
    only when all of the following hold:

    - it is an ``http`` or ``https`` URL with a host and no userinfo;
    - no query or fragment parameter is a known credential parameter, has a
      secret-like name (``client_secret``, ``auth``, ``x-api-key``, ...),
      carries an opaque token as its value, or nests a URL that carries a
      credential;
    - no path segment (including ``;`` path parameters) looks like an opaque
      token (for example a webhook or signed-URL secret) and no secret-like
      path segment (``token``, ``key``, ``secret``, ...) is followed by a
      value; API version segments such as ``v1`` are route words, not values.

    Anything else that merely parses as a URL is still treated as a credential.

    Args:
        value (str): The environment variable value to classify.
        patterns: Secret-like name substrings, normally the configured
            ``secret_env_name_patterns``.

    Returns:
        bool: True when the value is a URL that carries no credential.
    """
    try:
        url = urlsplit(value)
    except ValueError:
        return False

    if url.scheme not in ("http", "https") or not url.netloc:
        return False

    if url.username or url.password:
        return False

    for component in (url.query, url.fragment):
        if component and carries_credential_parameter(component, patterns):
            return False

    segments = [
        unquote(part)
        for segment in url.path.split("/")
        for part in segment.split(";")
        if part
    ]
    for index, segment in enumerate(segments):
        if looks_like_secret(segment):
            return False
        if is_credential_name(segment, patterns):
            if "=" in segment or ":" in segment:
                return False
            if index + 1 < len(segments) and looks_like_value(segments[index + 1]):
                return False

    return True


class machine_no_plaintext_secrets_in_env(Check):
    """Check if a Fly.io machine carries secret-like values in its plain config.

    Values placed in the machine's ``env`` block are stored in the machine
    configuration and returned in clear text by the Machines API to anyone who
    can read the app. Secrets belong in Fly secrets, which are encrypted at rest
    and only injected into the running machine.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine secrets handling check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []
        patterns = [
            pattern.upper()
            for pattern in config_value(
                machine_client.audit_config,
                "secret_env_name_patterns",
                DEFAULT_SECRET_NAME_PATTERNS,
            )
        ]

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)

            exposed = sorted(
                name
                for name, value in machine.env.items()
                if value
                and any(pattern in name.upper() for pattern in patterns)
                and not is_credential_free_url(value, patterns)
            )

            if not exposed:
                secrets = (
                    f"{len(machine.app_secret_names)} Fly secret(s) injected"
                    if machine.app_secret_names is not None
                    else "Fly secret names could not be read"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} has no "
                    f"secret-like values in its plain machine configuration "
                    f"({secrets})."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} exposes "
                    f"secret-like values in its plain machine configuration: "
                    f"{', '.join(exposed)}."
                )

            findings.append(report)

        return findings
