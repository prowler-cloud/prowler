from collections import defaultdict
from typing import Callable, Iterable, Optional

from cloudflare import NotFoundError
from pydantic import BaseModel

from prowler.lib.check.models import Check, CheckReportCloudflare

PERMISSION_DENIED = "PermissionDeniedError"
UNEXPECTED_VALUE = "UnexpectedValue"

ZONE_SETTINGS_READ = "Zone Settings Read"
DNS_READ = "DNS Read"
SSL_AND_CERTIFICATES_READ = "SSL and Certificates Read"
BOT_MANAGEMENT_READ = "Bot Management Read"
ZONE_WAF_READ = "Zone WAF Read"


def record_read_error(read_errors: dict, key: str, error: Exception) -> None:
    """Record why data could not be read; a 404 means not configured, so it is not recorded."""
    if not isinstance(error, NotFoundError):
        read_errors[key] = error.__class__.__name__


class CloudflareAccountResource(BaseModel):
    """Account-level resource for findings that cover every zone of an account."""

    id: str
    name: str
    account_id: str
    zone_name: str = "global"


def _cause(error: str, permission: str) -> str:
    if error == PERMISSION_DENIED:
        return f"the API token is missing the {permission} permission"
    if error == UNEXPECTED_VALUE:
        return "the Cloudflare API returned an unexpected value"
    return f"the Cloudflare API returned {error}"


def _manual_report(check: Check, resource, status_extended: str):
    report = CheckReportCloudflare(metadata=check.metadata(), resource=resource)
    report.status = "MANUAL"
    report.status_extended = status_extended
    return report


def split_unreadable_zones(
    check: Check,
    zones: Iterable,
    read_error: Callable[[object], Optional[str]],
    requirement: str,
    permission: str,
) -> tuple[list, list]:
    """Return MANUAL findings for zones whose data could not be read, and the readable zones."""
    zones_by_account = defaultdict(list)
    for zone in zones:
        zones_by_account[getattr(zone.account, "id", None)].append(zone)

    findings, readable = [], []
    for account_id, account_zones in zones_by_account.items():
        errors = [read_error(zone) for zone in account_zones]
        readable.extend(z for z, e in zip(account_zones, errors) if not e)

        if (
            account_id
            and len(account_zones) > 1
            and len(set(errors)) == 1
            and errors[0]
        ):
            account = account_zones[0].account
            findings.append(
                _manual_report(
                    check,
                    CloudflareAccountResource(
                        id=account.id, name=account.name, account_id=account.id
                    ),
                    f"Cannot evaluate {requirement} for any of the {len(account_zones)} "
                    f"zones in account {account.name}: {_cause(errors[0], permission)}.",
                )
            )
            continue

        for zone, error in zip(account_zones, errors):
            if error:
                findings.append(
                    _manual_report(
                        check,
                        zone,
                        f"Cannot evaluate {requirement} for zone {zone.name}: "
                        f"{_cause(error, permission)}.",
                    )
                )
    return findings, readable
