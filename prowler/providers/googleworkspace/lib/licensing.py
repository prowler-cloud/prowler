"""Google Workspace editions, read from the Enterprise License Manager API.

Google sells some audited features only on certain editions. Knowing which
editions a tenant holds lets a finding say when a missing feature is a matter
of the subscription rather than of configuration, the way the Vercel checks
explain plan-gated features.
"""

from typing import Optional

from prowler.lib.logger import logger

# The Licensing API has no read-only scope; Prowler only lists assignments.
LICENSING_SCOPE = "https://www.googleapis.com/auth/apps.licensing"
WORKSPACE_PRODUCT_ID = "Google-Apps"

# SKU ids as listed in the Licensing API products table:
# https://developers.google.com/workspace/admin/licensing/v1/how-tos/products
SKU_EDITIONS = {
    "1010020027": "Business Starter",
    "1010020028": "Business Standard",
    "1010020025": "Business Plus",
    "1010020029": "Enterprise Starter",
    "1010020026": "Enterprise Standard",
    "1010020020": "Enterprise Plus",
    "1010060001": "Essentials",
    "1010060003": "Enterprise Essentials",
    "1010060005": "Enterprise Essentials Plus",
    "1010020030": "Frontline Starter",
    "1010020031": "Frontline Standard",
    "1010020034": "Frontline Plus",
    "1010020035": "Business Continuity",
    "1010020036": "Business Continuity Plus",
    "Google-Apps-For-Business": "G Suite Basic",
    "Google-Apps-Unlimited": "G Suite Business",
    "Google-Apps-Lite": "G Suite Lite",
}


def fetch_editions(service, customer_id: str) -> list[str]:
    """Return the Google Workspace editions licensed to the customer.

    Reads every license assignment for the Google Workspace product and names
    each distinct SKU. An unknown SKU keeps the name the API gives, or its id.
    Returns an empty list when the API cannot be read, which callers treat as
    "edition unknown": the Licensing API needs its own scope and enablement,
    and nothing else depends on it.
    """
    if service is None:
        return []

    editions: set[str] = set()
    page_token: Optional[str] = None
    try:
        while True:
            response = (
                service.licenseAssignments()
                .listForProduct(
                    productId=WORKSPACE_PRODUCT_ID,
                    customerId=customer_id,
                    maxResults=1000,
                    pageToken=page_token,
                )
                .execute()
            )
            if not isinstance(response, dict):
                return []
            for item in response.get("items", []):
                sku_id = item.get("skuId", "")
                editions.add(SKU_EDITIONS.get(sku_id) or item.get("skuName") or sku_id)
            page_token = response.get("nextPageToken")
            if not page_token:
                break
    except Exception as error:
        logger.warning(
            f"Google Workspace editions could not be read "
            f"({error.__class__.__name__}: {error}). Findings will not say when a "
            f"feature is not sold on the tenant's edition. Enable the Enterprise "
            f"License Manager API and authorize the {LICENSING_SCOPE} scope to "
            f"add that context."
        )
        return []

    editions.discard("")
    return sorted(editions)


def edition_reason_suffix(
    editions, unsupported_editions: set[str], explanation: str
) -> str:
    """Return an edition-based explanation suffix only when the editions prove it.

    The suffix is added when every licensed edition lacks the feature; a tenant
    that also holds a supported edition gets no excuse, and unknown editions
    give none either. ``explanation`` may name the editions with ``{editions}``.
    """
    if not isinstance(editions, (list, tuple, set)) or not editions:
        return ""
    if not all(edition in unsupported_editions for edition in editions):
        return ""
    return (
        " This may be expected because "
        f"{explanation.format(editions=', '.join(editions))}"
    )
