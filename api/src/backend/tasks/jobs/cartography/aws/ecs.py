from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cartography.intel.aws import ecs as carto_ecs
from celery.utils.log import get_task_logger
from neo4j import GraphDatabase

from api.db_utils import rls_transaction
from api.models import Provider, Resource, ResourceScanSummary

logger = get_task_logger(__name__)


def sync_aws_ecs(
    tenant_id: str,
    provider_id: str,
    scan_id: Optional[str],
    regions: List[str],
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

        base_qs = Resource.objects.filter(provider_id=provider_id, service="ecs")
        if scan_id:
            rss_ids = ResourceScanSummary.objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, service="ecs"
            ).values_list("resource_id", flat=True)
            base_qs = base_qs.filter(id__in=list(rss_ids))
        if regions:
            base_qs = base_qs.filter(region__in=regions)

        ecs_resources = list(
            base_qs.only("uid", "name", "type", "region", "metadata", "details")
        )

    # Build in-memory maps for patched extractors
    clusters_by_region: Dict[str, List[Dict[str, Any]]] = {}
    cluster_arns_by_region: Dict[str, List[str]] = {}
    clusters_by_arn: Dict[str, Dict[str, Any]] = {}
    services_by_cluster: Dict[str, List[Dict[str, Any]]] = {}
    tasks_by_cluster: Dict[str, List[Dict[str, Any]]] = {}
    tds_by_arn: Dict[str, Dict[str, Any]] = {}
    container_instances_by_cluster: Dict[str, List[Dict[str, Any]]] = {}

    for r in ecs_resources:
        region = r.region or ""
        obj = _ecs_collect_items([r])[0]
        if r.type in ("cluster", "ecs_cluster"):
            arn = obj.get("clusterArn") or r.uid
            clusters_by_arn[arn] = obj
            cluster_arns_by_region.setdefault(region, []).append(arn)
            clusters_by_region.setdefault(region, []).append(obj)
        elif r.type in ("service", "ecs_service"):
            cluster_arn = obj.get("clusterArn") or _ecs_cluster_arn_from_uid(obj.get("_uid"), region, account_id)
            if cluster_arn:
                services_by_cluster.setdefault(cluster_arn, []).append(obj)
        elif r.type in ("task", "ecs_task"):
            cluster_arn = obj.get("clusterArn") or _ecs_cluster_arn_from_uid(obj.get("_uid"), region, account_id)
            if cluster_arn:
                tasks_by_cluster.setdefault(cluster_arn, []).append(obj)
            td_arn = obj.get("taskDefinitionArn")
            if td_arn:
                tds_by_arn.setdefault(td_arn, {"taskDefinitionArn": td_arn})
        elif r.type in ("task_definition", "ecs_task_definition"):
            arn = obj.get("taskDefinitionArn") or r.uid
            tds_by_arn[arn] = obj

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

    # Save originals references (not restored per request)
    def _patched_get_ecs_cluster_arns(_boto3_session, region):
        return cluster_arns_by_region.get(region, [])

    def _patched_get_ecs_clusters(_boto3_session, cluster_arns, region):
        return [clusters_by_arn.get(arn) for arn in cluster_arns if clusters_by_arn.get(arn)]

    def _patched_get_ecs_container_instances(_boto3_session, cluster_arn, region):
        return container_instances_by_cluster.get(cluster_arn, [])

    def _patched_get_ecs_services(_boto3_session, cluster_arn, region):
        return services_by_cluster.get(cluster_arn, [])

    def _patched_get_ecs_tasks(_boto3_session, cluster_arn, region):
        return tasks_by_cluster.get(cluster_arn, [])

    def _patched_get_ecs_task_definitions(_boto3_session, task_definition_arns, region):
        out = []
        for arn in task_definition_arns or []:
            td = tds_by_arn.get(arn)
            if td:
                out.append(td)
        return out

    # Apply patches
    setattr(carto_ecs, "get_ecs_cluster_arns", _patched_get_ecs_cluster_arns)
    setattr(carto_ecs, "get_ecs_clusters", _patched_get_ecs_clusters)
    setattr(carto_ecs, "get_ecs_container_instances", _patched_get_ecs_container_instances)
    setattr(carto_ecs, "get_ecs_services", _patched_get_ecs_services)
    setattr(carto_ecs, "get_ecs_tasks", _patched_get_ecs_tasks)
    setattr(carto_ecs, "get_ecs_task_definitions", _patched_get_ecs_task_definitions)

    try:
        with driver.session(database=database) if database else driver.session() as neo4j_session:
            class _Boto3SessionStub:
                pass

            boto3_session = _Boto3SessionStub()
            try:
                carto_ecs.sync(
                    neo4j_session,
                    boto3_session,
                    account_id,
                    regions,
                    update_tag,
                    common_job_parameters,
                )
            except TypeError:
                try:
                    carto_ecs.sync(
                        neo4j_session,
                        boto3_session,
                        account_id,
                        regions,
                        update_tag,
                    )
                except TypeError:
                    for region in regions or list(cluster_arns_by_region.keys()):
                        carto_ecs.sync(
                            neo4j_session,
                            boto3_session,
                            account_id,
                            region,
                            update_tag,
                            common_job_parameters,
                        )
    finally:
        try:
            driver.close()
        except Exception:
            pass

    return {"regions": len(regions or cluster_arns_by_region.keys())}


def _ecs_collect_items(resources: List[Resource]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for r in resources or []:
        payload = None
        for raw in (getattr(r, "metadata", None), getattr(r, "details", None)):
            if not raw:
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict):
                    payload = data
                    break
            except Exception:
                continue
        obj: Dict[str, Any] = payload.copy() if isinstance(payload, dict) else {}
        if r.uid:
            obj.setdefault("arn", r.uid)
        if r.name:
            obj.setdefault("clusterName", r.name)
            obj.setdefault("serviceName", r.name)
        if r.type in ("cluster", "ecs_cluster"):
            obj.setdefault("clusterArn", r.uid)
            if not obj.get("clusterName") and r.uid:
                obj["clusterName"] = r.uid.split("/")[-1]
        elif r.type in ("service", "ecs_service"):
            obj.setdefault("serviceArn", r.uid)
            if not obj.get("serviceName") and r.uid:
                obj["serviceName"] = r.uid.split("/")[-1]
        elif r.type in ("task", "ecs_task"):
            obj.setdefault("taskArn", r.uid)
        elif r.type in ("task_definition", "ecs_task_definition"):
            if "taskDefinition" in obj and isinstance(obj["taskDefinition"], dict):
                obj.update(obj["taskDefinition"])
            obj.setdefault("taskDefinitionArn", r.uid)
        obj["_uid"] = r.uid
        items.append(obj)
    return items


def _ecs_cluster_arn_from_uid(uid: Optional[str], region: str, account_id: str) -> Optional[str]:
    if not uid:
        return None
    if ":ecs:" in uid and ":cluster/" in uid:
        return uid
    name = uid.split("/")[-1]
    return f"arn:aws:ecs:{region}:{account_id}:cluster/{name}"
