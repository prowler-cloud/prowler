import ipaddress
import socket
import string
from collections.abc import Iterable
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

LIGHTHOUSE_OPENAI_COMPATIBLE_ALLOWED_SCHEMES = frozenset({"https"})
LIGHTHOUSE_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "localhost",
        "metadata.google.internal",
    }
)


def _normalize_hostname(hostname: str) -> str:
    return hostname.rstrip(".").lower()


def _configured_lighthouse_allowed_hosts() -> tuple[str, ...]:
    allowed_hosts = getattr(settings, "LIGHTHOUSE_OPENAI_COMPATIBLE_ALLOWED_HOSTS", ())
    return tuple(host for host in allowed_hosts if host)


def _is_allowed_lighthouse_host(hostname: str, allowed_hosts: Iterable[str]) -> bool:
    normalized_allowed_hosts = [
        _normalize_hostname(host.lstrip(".")) for host in allowed_hosts
    ]
    return any(
        hostname == allowed_host or hostname.endswith(f".{allowed_host}")
        for allowed_host in normalized_allowed_hosts
    )


def _validate_lighthouse_public_ip(address: str) -> None:
    ip_address = ipaddress.ip_address(address)
    if not ip_address.is_global:
        raise ValidationError(
            _("Base URL must use an external public endpoint."),
            code="lighthouse_base_url_not_public",
        )


def validate_lighthouse_openai_compatible_base_url(
    base_url: str,
    *,
    allowed_hosts: Iterable[str] | None = None,
    resolve_dns: bool = True,
) -> None:
    """Validate an OpenAI-compatible Lighthouse base URL before outbound use."""
    parsed = urlparse(str(base_url))
    if parsed.scheme.lower() not in LIGHTHOUSE_OPENAI_COMPATIBLE_ALLOWED_SCHEMES:
        raise ValidationError(
            _("Base URL must use HTTPS."),
            code="lighthouse_base_url_invalid_scheme",
        )

    if not parsed.hostname:
        raise ValidationError(
            _("Base URL must include a host."),
            code="lighthouse_base_url_missing_host",
        )

    try:
        port = parsed.port or 443
    except ValueError as error:
        raise ValidationError(
            _("Base URL port is invalid."),
            code="lighthouse_base_url_invalid_port",
        ) from error

    hostname = _normalize_hostname(parsed.hostname)
    if hostname in LIGHTHOUSE_BLOCKED_METADATA_HOSTS or hostname.endswith(".localhost"):
        raise ValidationError(
            _("Base URL must use an external public endpoint."),
            code="lighthouse_base_url_blocked_host",
        )

    configured_allowed_hosts = (
        tuple(allowed_hosts)
        if allowed_hosts is not None
        else _configured_lighthouse_allowed_hosts()
    )
    if configured_allowed_hosts and not _is_allowed_lighthouse_host(
        hostname, configured_allowed_hosts
    ):
        raise ValidationError(
            _("Base URL host is not an approved provider."),
            code="lighthouse_base_url_unapproved_host",
        )

    try:
        _validate_lighthouse_public_ip(hostname)
    except ValueError:
        if not resolve_dns:
            return
    else:
        return

    try:
        resolved_addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValidationError(
            _("Base URL host could not be resolved."),
            code="lighthouse_base_url_resolution_failed",
        ) from error

    if not resolved_addresses:
        raise ValidationError(
            _("Base URL host could not be resolved."),
            code="lighthouse_base_url_resolution_failed",
        )

    for resolved_address in resolved_addresses:
        socket_address = resolved_address[4]
        _validate_lighthouse_public_ip(socket_address[0])


class MaximumLengthValidator:
    def __init__(self, max_length=72):
        self.max_length = max_length

    def validate(self, password, user=None):
        del user
        if len(password) > self.max_length:
            raise ValidationError(
                _(
                    "This password is too long. It must contain no more than %(max_length)d characters."
                ),
                code="password_too_long",
                params={"max_length": self.max_length},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain no more than {self.max_length} characters."
        )


class SpecialCharactersValidator:
    def __init__(self, special_characters=None, min_special_characters=1):
        # Use string.punctuation if no custom characters provided
        self.special_characters = special_characters or string.punctuation
        self.min_special_characters = min_special_characters

    def validate(self, password, user=None):
        del user
        if (
            sum(1 for char in password if char in self.special_characters)
            < self.min_special_characters
        ):
            raise ValidationError(
                _("This password must contain at least one special character."),
                code="password_no_special_characters",
                params={
                    "special_characters": self.special_characters,
                    "min_special_characters": self.min_special_characters,
                },
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least one special character from: {self.special_characters}"
        )


class UppercaseValidator:
    def __init__(self, min_uppercase=1):
        self.min_uppercase = min_uppercase

    def validate(self, password, user=None):
        del user
        if sum(1 for char in password if char.isupper()) < self.min_uppercase:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_uppercase)d uppercase letter."
                ),
                code="password_no_uppercase_letters",
                params={"min_uppercase": self.min_uppercase},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_uppercase} uppercase letter."
        )


class LowercaseValidator:
    def __init__(self, min_lowercase=1):
        self.min_lowercase = min_lowercase

    def validate(self, password, user=None):
        del user
        if sum(1 for char in password if char.islower()) < self.min_lowercase:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_lowercase)d lowercase letter."
                ),
                code="password_no_lowercase_letters",
                params={"min_lowercase": self.min_lowercase},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_lowercase} lowercase letter."
        )


class NumericValidator:
    def __init__(self, min_numeric=1):
        self.min_numeric = min_numeric

    def validate(self, password, user=None):
        del user
        if sum(1 for char in password if char.isdigit()) < self.min_numeric:
            raise ValidationError(
                _(
                    "This password must contain at least %(min_numeric)d numeric character."
                ),
                code="password_no_numeric_characters",
                params={"min_numeric": self.min_numeric},
            )

    def get_help_text(self):
        return _(
            f"Your password must contain at least {self.min_numeric} numeric character."
        )
