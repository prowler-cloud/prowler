from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cartography.intel.aws import iam as carto_iam
from celery.utils.log import get_task_logger
from neo4j import GraphDatabase

from api.db_utils import rls_transaction
from api.models import Provider, Resource, ResourceScanSummary

logger = get_task_logger(__name__)


def sync_aws_iam(
    tenant_id: str,
    provider_id: str,
    scan_id: Optional[str],
    neo4j_conf: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        from neo4j import GraphDatabase as _  # ensure import present
    except Exception as e:
        logger.error(f"Neo4j not available: {e}")
        return {"error": str(e)}

    with rls_transaction(tenant_id):
        provider = Provider.objects.get(pk=provider_id)
        account_id = provider.uid

        base_qs = Resource.objects.filter(
            provider_id=provider_id, service="iam", type__in=["role", "iam_role"]
        )
        if scan_id:
            rss_ids = ResourceScanSummary.objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, service="iam"
            ).values_list("resource_id", flat=True)
            base_qs = base_qs.filter(id__in=list(rss_ids))
        role_resources = list(
            base_qs.only("uid", "name", "metadata", "details", "inserted_at")
        )

    roles: List[Dict[str, Any]] = []
    for r in role_resources:
        role_obj: Dict[str, Any] = {
            "Arn": r.uid,
            "RoleName": r.name or r.uid.split("/")[-1],
            "RoleId": r.uid.split("/")[-1],
            "Path": "/",
            "CreateDate": (r.inserted_at or datetime.now(tz=timezone.utc)).isoformat(),
            "AssumeRolePolicyDocument": {"Statement": []},
        }
        for raw in (getattr(r, "metadata", None), getattr(r, "details", None)):
            if not raw:
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            pol = (
                data.get("AssumeRolePolicyDocument")
                or data.get("AssumeRolePolicy")
                or data.get("assume_role_policy_document")
            )
            if pol and isinstance(pol, dict) and pol.get("Statement"):
                role_obj["AssumeRolePolicyDocument"] = pol
                break
        roles.append(role_obj)

    uri = neo4j_conf.get("uri")
    user = neo4j_conf.get("user") or neo4j_conf.get("username")
    password = neo4j_conf.get("password")
    database = neo4j_conf.get("database")
    if not all([uri, user, password]):
        logger.error("Neo4j configuration incomplete: require uri, user, password")
        return {"error": "missing_neo4j_config"}

    update_tag = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    common_job_parameters = {"UPDATE_TAG": update_tag, "AWS_ID": account_id}
    driver = GraphDatabase.driver(uri, auth=(user, password))

    # Provide minimal patches for IAM getters
    def _patched_get_iam_roles(_boto3_session):
        return roles

    def _empty_list(*args, **kwargs):
        return []

    setattr(carto_iam, "get_iam_roles", _patched_get_iam_roles)
    # Some versions may use list_roles instead
    if hasattr(carto_iam, "list_roles"):
        setattr(carto_iam, "list_roles", _patched_get_iam_roles)
    for fname in [
        "get_iam_users",
        "get_iam_groups",
        "get_iam_policies",
        "get_iam_role_inline_policies",
        "get_iam_role_attached_policies",
        "get_iam_instance_profiles",
    ]:
        if hasattr(carto_iam, fname):
            setattr(carto_iam, fname, _empty_list)

    try:
        with driver.session(database=database) if database else driver.session() as neo4j_session:
            class _Boto3SessionStub:
                pass

            boto3_session = _Boto3SessionStub()
            try:
                carto_iam.sync(
                    neo4j_session,
                    boto3_session,
                    account_id,
                    update_tag,
                    common_job_parameters,
                )
            except TypeError:
                carto_iam.sync(
                    neo4j_session,
                    boto3_session,
                    account_id,
                    update_tag,
                )
    finally:
        try:
            driver.close()
        except Exception:
            pass

    return {"roles": len(roles)}
