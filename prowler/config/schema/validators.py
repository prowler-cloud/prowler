"""Reusable field validators shared across provider config schemas.

These are factored out so multiple providers can reuse the same validation
logic (version strings, port ranges, IP/CIDR entries) instead of duplicating
it per schema. Each validator accepts ``None`` so optional fields stay valid
when the key is absent.
"""

from ipaddress import ip_network
from typing import Callable, Optional

_VERSION_PART_LABELS = ("X", "Y", "Z", "W")


def make_dotted_version_validator(
    min_parts: int, max_parts: int
) -> Callable[[Optional[str]], Optional[str]]:
    """Build a validator for dotted numeric version strings.

    The returned validator accepts ``None`` and strings made of between
    ``min_parts`` and ``max_parts`` dot-separated numeric components. Anything
    else raises ``ValueError``.

    Examples:
        ``make_dotted_version_validator(3, 3)`` accepts ``"1.4.0"`` (semver).
        ``make_dotted_version_validator(2, 2)`` accepts ``"1.28"`` (EKS minor).
        ``make_dotted_version_validator(1, 2)`` accepts ``"17"`` or ``"8.2"``.
    """
    if min_parts == max_parts:
        expected = ".".join(_VERSION_PART_LABELS[:min_parts])
    else:
        expected = " or ".join(
            f"'{'.'.join(_VERSION_PART_LABELS[:n])}'"
            for n in range(min_parts, max_parts + 1)
        )

    def _validate(v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parts = v.split(".")
        if not (min_parts <= len(parts) <= max_parts) or not all(
            p.isdigit() for p in parts
        ):
            raise ValueError(f"{v!r} is not a valid version (expected {expected})")
        return v

    return _validate


def validate_port_range(v: Optional[list[int]]) -> Optional[list[int]]:
    """Reject ports outside the valid ``1..65535`` range."""
    if v is None:
        return v
    for port in v:
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is outside the valid range 1..65535")
    return v


def validate_ip_networks(v: Optional[list[str]]) -> Optional[list[str]]:
    """Reject entries that are not a valid IP address or CIDR network."""
    if v is None:
        return v
    for entry in v:
        try:
            ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"entry {entry!r} is not a valid IP or CIDR ({exc})"
            ) from exc
    return v
