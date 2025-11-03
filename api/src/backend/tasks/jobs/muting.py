from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from tasks.utils import batched

from api.db_utils import rls_transaction
from api.models import Finding, MuteRule

logger = get_task_logger(__name__)


def mute_historical_findings(tenant_id: str, mute_rule_id: str):
    """
    Mute historical findings that match the given mute rule.

    This function processes findings in batches, updating their muted status
    and adding the mute reason.

    Args:
        tenant_id (str): The tenant ID for RLS context
        mute_rule_id (str): The ID of the mute rule to apply

    Returns:
        dict: Summary of the muting operation with findings_muted count
    """
    findings_muted_count = 0

    # Get the list of UIDs to mute and the reason
    with rls_transaction(tenant_id):
        mute_rule = MuteRule.objects.get(id=mute_rule_id, tenant_id=tenant_id)
        finding_uids = mute_rule.finding_uids
        mute_reason = mute_rule.reason
        muted_at = mute_rule.inserted_at

    # Query findings that match the UIDs and are not already muted
    with rls_transaction(tenant_id):
        findings_to_mute = Finding.objects.filter(
            tenant_id=tenant_id, uid__in=finding_uids, muted=False
        )
        total_findings = findings_to_mute.count()

        logger.info(
            f"Processing {total_findings} findings for mute rule {mute_rule_id}"
        )

        if total_findings > 0:
            for batch, is_last in batched(
                findings_to_mute.iterator(), DJANGO_FINDINGS_BATCH_SIZE
            ):
                batch_ids = [f.id for f in batch]
                updated_count = Finding.all_objects.filter(
                    id__in=batch_ids, tenant_id=tenant_id
                ).update(
                    muted=True,
                    muted_at=muted_at,
                    muted_reason=mute_reason,
                )
                findings_muted_count += updated_count

    logger.info(f"Muted {findings_muted_count} findings for rule {mute_rule_id}")

    return {
        "findings_muted": findings_muted_count,
        "rule_id": mute_rule_id,
    }
