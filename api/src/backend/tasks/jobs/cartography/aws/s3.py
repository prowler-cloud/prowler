import json

from datetime import datetime, timezone
from typing import Any, Generator

import neo4j

from cartography.intel.aws import s3 as cartography_s3
from celery.utils.log import get_task_logger

from api.db_utils import rls_transaction
from api.models import Provider, Resource, ResourceScanSummary

logger = get_task_logger(__name__)


def sync_aws_s3(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Monkey-patch Cartography S3 extractors and call cartography.intel.aws.s3.sync.

    Patched functions:
      - get_s3_bucket_list
      - get_s3_bucket_details
      - _sync_s3_notifications (uses Prowler data and Cartography's original _load_s3_notifications)
    """

    with rls_transaction(tenant_id):
        provider = Provider.objects.get(pk=provider_id)
        account_id = provider.uid

    bucket_list = _build_s3_bucket_list(tenant_id, provider_id, scan_id, regions)
    bucket_data = _build_s3_bucket_details(bucket_list)
    bucket_notifications = _build_s3_notifications(tenant_id, provider_id, scan_id, regions)

    def _patched_get_s3_bucket_list(_boto3_session):
        return bucket_list

    def _patched_get_s3_bucket_details(_boto3_session, _bucket_data):
        return bucket_data

    def _patched_sync_s3_notifications(_neo4j_session, _boto3_session, _bucket_data, _update_tag):
        cartography_s3._load_s3_notifications(_neo4j_session, bucket_notifications, _update_tag)

    # Apply patches without restoring originals by request
    setattr(cartography_s3, "get_s3_bucket_list", _patched_get_s3_bucket_list)
    setattr(cartography_s3, "get_s3_bucket_details", _patched_get_s3_bucket_details)
    setattr(cartography_s3, "_sync_s3_notifications", _patched_sync_s3_notifications)

    cartography_s3.sync(
        neo4j_session,
        None,
        account_id,
        update_tag,
        common_job_parameters,
    )

    # Stats
    bucket_notifications_count = 0
    for bn in bucket_notifications:
        bucket_notifications_count += len(bn.get("TopicConfigurations", []) or [])
        bucket_notifications_count += len(bn.get("QueueConfigurations", []) or [])
        bucket_notifications_count += len(bn.get("LambdaFunctionConfigurations", []) or [])

    return {"buckets": len(bucket_data.get("Buckets", [])), "notifications": bucket_notifications_count}


def _build_s3_bucket_list(
    tenant_id: str,
    provider_id: str,
    scan_id: str | None,
    regions: list[str],
) -> dict[str, Any]:
    bucket_items: list[dict[str, Any]] = []

    with rls_transaction(tenant_id):
        base_qs = Resource.objects.filter(
            provider_id=provider_id,
            service="s3",
            type__in=["bucket", "s3_bucket"],
        )
        if scan_id:
            rss_ids = ResourceScanSummary.objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, service="s3"
            ).values_list("resource_id", flat=True)
            base_qs = base_qs.filter(id__in=list(rss_ids))
        if regions:
            base_qs = base_qs.filter(region__in=regions)

        resources = list(base_qs.only("name", "region", "metadata", "uid", "inserted_at"))

    owner: dict[str, Any] = {"DisplayName": None, "ID": None}

    for r in resources:
        name = r.name or _s3_derive_bucket_name_from_uid(r.uid)
        creation_date = (
            datetime.now(tz=timezone.utc).isoformat()
            if not getattr(r, "inserted_at", None)
            else r.inserted_at.replace(tzinfo=timezone.utc).isoformat()
        )
        bucket_items.append({"Name": name, "CreationDate": creation_date, "Region": r.region})

    return {"Owner": owner, "Buckets": bucket_items}


def _s3_derive_bucket_name_from_uid(uid: str) -> str:
    if uid and ":s3:::" in uid:
        try:
            return uid.split(":s3:::", 1)[1]
        except Exception:
            return uid
    return uid or "unknown-bucket"


def _build_s3_bucket_details(
    bucket_data: dict[str, Any],
) -> Generator[
    tuple[
        str,
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
        dict[str, Any] | None,
    ],
    None,
    None,
]:
    for b in bucket_data.get("Buckets", []):
        yield (b["Name"], None, None, None, None, None, None, None)


def _build_s3_notifications(
    tenant_id: str,
    provider_id: str,
    scan_id: str | None,
    regions: list[str],
) -> list[dict[str, Any]]:
    """
    Return a list of per-bucket notifications.

    Shape (best-effort, Cartography-compatible):
      {
        "bucket": <bucket-name>,
        "TopicConfigurations": [...],
        "QueueConfigurations": [...],
        "LambdaFunctionConfigurations": [...],
        "EventBridgeConfiguration": {...} | None,
      }
    """

    notifications: list[dict[str, Any]] = []

    with rls_transaction(tenant_id):
        base_qs = Resource.objects.filter(
            provider_id=provider_id,
            service="s3",
            type__in=["bucket", "s3_bucket"],
        )
        if scan_id:
            rss_ids = ResourceScanSummary.objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, service="s3"
            ).values_list("resource_id", flat=True)
            base_qs = base_qs.filter(id__in=list(rss_ids))
        if regions:
            base_qs = base_qs.filter(region__in=regions)

        resources = list(base_qs.only("name", "metadata", "details", "uid"))

    for r in resources:
        name = r.name or _s3_derive_bucket_name_from_uid(r.uid)
        conf_obj: dict[str, Any] | None= None

        for raw in (getattr(r, "metadata", None), getattr(r, "details", None)):
            if not raw:
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                continue

            candidate = data.get("notification_config") if isinstance(data, dict) else None
            if not candidate and isinstance(data, dict):
                has_keys = any(
                    k in data
                    for k in (
                        "TopicConfigurations",
                        "QueueConfigurations",
                        "LambdaFunctionConfigurations",
                        "EventBridgeConfiguration",
                    )
                )
                if has_keys:
                    candidate = data

            if candidate and isinstance(candidate, dict):
                conf_obj = candidate
                break

        if not conf_obj:
            continue

        notification = {
            "bucket": name,
            "TopicConfigurations": conf_obj.get("TopicConfigurations") or [],
            "QueueConfigurations": conf_obj.get("QueueConfigurations") or [],
            "LambdaFunctionConfigurations": conf_obj.get("LambdaFunctionConfigurations") or [],
            "EventBridgeConfiguration": conf_obj.get("EventBridgeConfiguration"),
        }
        notifications.append(notification)

    return notifications
