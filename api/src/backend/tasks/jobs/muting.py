from collections.abc import Iterable

from api.db_utils import rls_transaction
from api.models import Finding, MuteRule, Scan, StateChoices
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def _mute_findings_for_rule(
    *,
    tenant_id: str,
    scan_id: str,
    finding_uids: Iterable[str],
    muted_at,
    muted_reason: str,
) -> int:
    finding_uids = list(finding_uids)
    if not finding_uids:
        return 0

    return Finding.all_objects.filter(
        tenant_id=tenant_id,
        scan_id=scan_id,
        uid__in=finding_uids,
        muted=False,
    ).update(
        muted=True,
        muted_at=muted_at,
        muted_reason=muted_reason,
    )


def mute_findings_in_latest_scans(
    tenant_id: str, mute_rule_id: str, provider_ids: list[str]
) -> dict:
    """Apply a mute rule to the latest completed scan of each provider."""
    provider_ids = list(dict.fromkeys(provider_ids))

    with rls_transaction(tenant_id):
        mute_rule = MuteRule.objects.get(id=mute_rule_id, tenant_id=tenant_id)
        latest_scans = list(
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id__in=provider_ids,
                state=StateChoices.COMPLETED,
                completed_at__isnull=False,
            )
            .order_by("provider_id", "-completed_at", "-inserted_at", "-id")
            .distinct("provider_id")
            .values_list("id", flat=True)
        )

        changed_scan_ids = []
        findings_muted = 0
        for scan_id in latest_scans:
            updated = _mute_findings_for_rule(
                tenant_id=tenant_id,
                scan_id=str(scan_id),
                finding_uids=mute_rule.finding_uids,
                muted_at=mute_rule.inserted_at,
                muted_reason=mute_rule.reason,
            )
            if updated:
                findings_muted += updated
                changed_scan_ids.append(str(scan_id))

    logger.info(
        "Muted %d findings in %d latest scans for rule %s",
        findings_muted,
        len(changed_scan_ids),
        mute_rule_id,
    )
    return {
        "findings_muted": findings_muted,
        "rule_id": mute_rule_id,
        "scan_ids": changed_scan_ids,
    }


def reconcile_scan_mute_rules(tenant_id: str, scan_id: str) -> dict:
    """Apply the current enabled mute rules to one completed scan."""
    findings_muted = 0

    with rls_transaction(tenant_id):
        mute_rules = MuteRule.objects.filter(tenant_id=tenant_id, enabled=True).values(
            "finding_uids", "reason", "inserted_at"
        )

        for mute_rule in mute_rules:
            findings_muted += _mute_findings_for_rule(
                tenant_id=tenant_id,
                scan_id=scan_id,
                finding_uids=mute_rule["finding_uids"],
                muted_at=mute_rule["inserted_at"],
                muted_reason=mute_rule["reason"],
            )

    logger.info(
        "Reconciled mute rules for scan %s; muted %d findings",
        scan_id,
        findings_muted,
    )
    return {"findings_muted": findings_muted, "scan_id": str(scan_id)}
