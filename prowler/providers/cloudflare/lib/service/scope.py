"""Helpers shared by Cloudflare account-level services and checks."""

from typing import Any, ClassVar, Iterable

from pydantic import BaseModel

from prowler.lib.check.models import Check, CheckReportCloudflare


class CloudflareAccountScope(BaseModel):
    """Account-level resource used for findings that are not tied to a resource."""

    id: str
    name: str
    account_id: str
    # Account-scoped resources are not zone resources: report them as global.
    is_global_resource: ClassVar[bool] = True


def account_scope(client: Any, account_id: str) -> CloudflareAccountScope:
    """Build the account-level resource for ``account_id``.

    Args:
        client: A Cloudflare service client (exposes ``provider``).
        account_id: Cloudflare account ID.

    Returns:
        The account scope, named after the account when it is known.
    """
    accounts = getattr(getattr(client.provider, "identity", None), "accounts", [])
    name = next(
        (a.name for a in accounts or [] if a.id == account_id and a.name), account_id
    )
    return CloudflareAccountScope(id=account_id, name=name, account_id=account_id)


def manual_account_report(
    check: Check, client: Any, account_id: str, message: str
) -> CheckReportCloudflare:
    """Build one account-level MANUAL finding for data that could not be retrieved.

    Args:
        check: The check emitting the finding.
        client: The Cloudflare service client the check reads from.
        account_id: The account whose data could not be retrieved.
        message: Explanation naming the missing permission or API.

    Returns:
        A MANUAL CheckReportCloudflare for the account.
    """
    report = CheckReportCloudflare(
        metadata=check.metadata(), resource=account_scope(client, account_id)
    )
    report.status = "MANUAL"
    report.status_extended = message
    return report


def collect_pages(listing: Any, key: str = "id") -> list:
    """Read every item of a paginated Cloudflare listing.

    Duplicate items (pages overlapping the previous one) are skipped. Reading
    stops if a whole page only repeats known items, because the SDK paginator
    otherwise requests ``page + 1`` forever when the API ignores the page
    parameter. Errors propagate so callers can discard partial results.

    Args:
        listing: An SDK paginator, or a plain iterable of items.
        key: Attribute that identifies an item.

    Returns:
        The unique items, in API order.
    """
    pages: Iterable = (
        (page.result or [] for page in listing.iter_pages())
        if hasattr(listing, "iter_pages") and not isinstance(listing, (list, tuple))
        else [list(listing)]
    )
    items, seen = [], set()
    for page in pages:
        page = list(page)
        new_items = []
        for item in page:
            item_id = getattr(item, key, None)
            if item_id in seen:
                continue
            if item_id is not None:
                seen.add(item_id)
            new_items.append(item)
        if page and not new_items:
            break
        items.extend(new_items)
    return items
