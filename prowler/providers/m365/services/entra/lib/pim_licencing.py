"""Helper to determine whether the tenant is licensed for PIM.

Privileged Identity Management requires a Microsoft Entra ID P2 or
Microsoft Entra ID Governance licence.  This module checks subscribed SKUs
for the relevant service plan names.

Reference:
    https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference
"""

from typing import List, Optional

from prowler.providers.m365.services.entra.entra_service import SubscribedSku

# Service plan names that indicate PIM availability.
PIM_SERVICE_PLAN_NAMES = {
    "AAD_PREMIUM_P2",
    "ENTRA_ID_GOVERNANCE",
    "AAD_PREMIUM_P2_GOVERNANCE",
}


def has_pim_licence(subscribed_skus: Optional[List[SubscribedSku]]) -> Optional[bool]:
    """Check whether the tenant has a licence that enables PIM.

    Args:
        subscribed_skus: The parsed subscribed SKUs from Entra service.
            ``None`` means the data could not be retrieved.

    Returns:
        ``True`` if PIM is licensed, ``False`` if not, or ``None`` when
        licence status is unknown (SKUs could not be read).
    """
    if subscribed_skus is None:
        return None

    for sku in subscribed_skus:
        if sku.capability_status != "Enabled":
            continue
        for plan_name in sku.service_plan_names:
            if plan_name in PIM_SERVICE_PLAN_NAMES:
                return True
    return False
