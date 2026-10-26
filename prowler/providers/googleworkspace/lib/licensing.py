"""Google Workspace editions, read from the Enterprise License Manager API.

Google sells some audited features only on certain editions. Knowing which
editions a tenant holds lets a finding say when a missing feature is a matter
of the subscription rather than of configuration, the way the Vercel checks
explain plan-gated features.
"""

from typing import Optional

from googleapiclient.errors import HttpError

from prowler.lib.logger import logger

# The Licensing API has no read-only scope; Prowler only lists assignments.
LICENSING_SCOPE = "https://www.googleapis.com/auth/apps.licensing"
WORKSPACE_PRODUCT_ID = "Google-Apps"
# Cloud Identity Premium is a product of its own that a user can hold next to
# a Workspace license. Google grants it some gated features (DLP for Drive,
# Google session control), so a tenant that holds it never gets an excuse.
CLOUD_IDENTITY_PREMIUM_PRODUCT_ID = "101005"
CLOUD_IDENTITY_PREMIUM = "Cloud Identity Premium"

# SKU ids as listed in the Licensing API products table:
# https://developers.google.com/workspace/admin/licensing/v1/how-tos/products
# Education SKUs live under other products (Google-Apps-For-Education, 101031,
# 101037) and are not read: an Education tenant reports no editions and its
# findings carry no edition context.
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

# Google, "About DLP for Drive", lists the supported editions: Frontline
# Standard and Plus, Enterprise Standard and Plus, Education Fundamentals,
# Standard and Plus, and Enterprise Essentials Plus. The set names the editions
# Google sells today without it. The legacy G Suite Business and the Business
# Continuity SKUs are left out on purpose: Google documents no entitlement for
# them either way, so they get no excuse.
EDITIONS_WITHOUT_DRIVE_DLP = {
    "Business Starter",
    "Business Standard",
    "Business Plus",
    "Enterprise Starter",
    "Enterprise Essentials",
    "Essentials",
    "Frontline Starter",
    "G Suite Basic",
    "G Suite Lite",
}
DRIVE_DLP_EXPLANATION = (
    "Drive data protection rules are not available on the Google Workspace "
    "{editions}."
)

# Google, "Set session length for Google services", lists the supported
# editions: Frontline Standard and Plus, Business Plus, Enterprise Standard and
# Plus, Education Fundamentals, Standard and Plus, Enterprise Essentials Plus,
# G Suite Business and Cloud Identity Premium. The Admin console has no Google
# session control page on the other editions. The set names the editions
# Google sells today without it; the Business Continuity SKUs are left out
# because Google lists them neither way.
EDITIONS_WITHOUT_SESSION_CONTROL = {
    "Business Starter",
    "Business Standard",
    "Enterprise Starter",
    "Enterprise Essentials",
    "Essentials",
    "Frontline Starter",
    "G Suite Basic",
    "G Suite Lite",
}
SESSION_CONTROL_EXPLANATION = (
    "Google session control is not available on the Google Workspace {editions}."
)

# Google, "Manage shared drives as an admin": the default sharing settings are
# "Not supported for Business Starter. All shared drive sharing settings are
# set to allow." The Admin console greys the controls out on that edition and
# new shared drives allow every sharing option; a tenant downgraded from
# another edition may still display its earlier values. Only Business Starter
# is named because Google documents the behaviour for it alone. Editions
# missing from the supported list (Frontline Starter and Standard, Enterprise
# Starter, G Suite Basic and Lite) get no excuse.
EDITIONS_WITHOUT_SHARED_DRIVE_SETTINGS = {"Business Starter"}
SHARED_DRIVE_SETTINGS_EXPLANATION = (
    "shared drive settings cannot be changed on the Google Workspace {editions}, "
    "where new shared drives allow every sharing option."
)


def fetch_editions(service, customer_id: str) -> list[str]:
    """Return the Google Workspace editions licensed to the customer.

    Reads every license assignment for the Google Workspace product and names
    each distinct SKU. An unknown SKU keeps the name the API gives, or its id.
    Cloud Identity Premium is read as a presence test on its own product and
    listed as an edition when any user holds it.
    Returns an empty list when the API cannot be read, which callers treat as
    "edition unknown": the Licensing API needs its own scope and enablement,
    and nothing else depends on it.
    """
    if service is None:
        return []

    try:
        editions = _workspace_editions(service, customer_id)
        if editions is None:
            # A client that is not wired for licensing (a bare mock in the
            # check tests) answers with something that is not a page.
            return []
        if _has_cloud_identity_premium(service, customer_id):
            editions.add(CLOUD_IDENTITY_PREMIUM)
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


def _workspace_editions(service, customer_id: str) -> Optional[set[str]]:
    """Name every Google Workspace SKU assigned to a user, across all pages."""
    editions: set[str] = set()
    page_token: Optional[str] = None
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
            return None
        for item in response.get("items", []):
            sku_id = item.get("skuId", "")
            editions.add(SKU_EDITIONS.get(sku_id) or item.get("skuName") or sku_id)
        page_token = response.get("nextPageToken")
        if not page_token:
            return editions


def _has_cloud_identity_premium(service, customer_id: str) -> bool:
    """Tell whether any user holds a Cloud Identity Premium license.

    One assignment is enough, so a single entry is requested. Google does not
    document how the API answers for a product the customer never subscribed
    to: an empty page and a 400 or 404 both mean "not held" here, since the
    Google Workspace listing just succeeded with the same credentials and
    customer id. Any other failure propagates and leaves the editions unknown,
    so no finding claims the feature is missing.
    """
    try:
        response = (
            service.licenseAssignments()
            .listForProduct(
                productId=CLOUD_IDENTITY_PREMIUM_PRODUCT_ID,
                customerId=customer_id,
                maxResults=1,
            )
            .execute()
        )
    except HttpError as error:
        if error.resp.status in (400, 404):
            return False
        raise
    return isinstance(response, dict) and bool(response.get("items"))


def edition_reason_suffix(
    editions, unsupported_editions: set[str], explanation: str
) -> str:
    """Return an edition-based explanation suffix only when the editions prove it.

    The suffix is added when every licensed edition lacks the feature; a tenant
    that also holds a supported edition gets no excuse, and unknown editions
    give none either. ``explanation`` may name the editions with ``{editions}``,
    which expands to "Business Starter edition" or "Business Standard and
    Business Starter editions".
    """
    # The check tests run with a bare mock provider whose editions attribute
    # is a mock as well; anything that is not a real sequence counts as unknown.
    if not isinstance(editions, (list, tuple, set)) or not editions:
        return ""
    if not all(edition in unsupported_editions for edition in editions):
        return ""
    return (
        " This may be expected because "
        f"{explanation.format(editions=_edition_phrase(editions))}"
    )


def _edition_phrase(editions) -> str:
    names = list(editions)
    if len(names) == 1:
        return f"{names[0]} edition"
    return f"{', '.join(names[:-1])} and {names[-1]} editions"
