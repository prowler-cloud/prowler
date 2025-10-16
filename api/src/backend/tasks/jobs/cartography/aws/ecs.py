import json

from collections import defaultdict
from typing import Any

import neo4j

from cartography.intel.aws import ecs as cartography_ecs
from celery.utils.log import get_task_logger

from api.db_utils import rls_transaction
from api.models import Resource, ResourceScanSummary

# TODO: Do the rigth logging setup
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger
logger = logging.getLogger(BackendLogger.API)


def sync_aws_ecs(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Entry point for syncing AWS ECS data into Cartography.
    """

    clusters_region_metadata = _get_ecs_clusters_region_metadata(tenant_id, provider_id, scan_id, regions)

    # Calling our version of cartography AWS ECS sync
    return _sync(
        neo4j_session,
        account_id,
        clusters_region_metadata,
        update_tag,
        common_job_parameters,
    )


def _get_ecs_clusters_region_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """
    Getting ECS clusters metadata from Prowler DB.
    """

    with rls_transaction(tenant_id):
        clusters_qs = Resource.objects.filter(
            provider_id=provider_id,
            service="ecs",
            type="AwsEcsCluster",
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="ecs",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    clusters_region_metadata = defaultdict(list)
    for cluster in clusters_qs:
        cluster_metadata = json.loads(cluster.metadata)
        cluster_metadata["inserted_at"] = cluster.inserted_at
        clusters_region_metadata[cluster_metadata.get("region")].append(cluster_metadata)

    return clusters_region_metadata


def _sync(
    neo4j_session: neo4j.Session,
    account_id: str,
    clusters_region_metadata: dict[str, list[dict[str, Any]]],
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Code based on `cartography.intel.aws.ecs.sync`.
    """
    for region in clusters_region_metadata.keys():
        clusters_metadata = clusters_region_metadata[region]
        cluster_arns = [cluster.get("arn") for cluster in clusters_metadata]

        _sync_ecs_clusters(
            neo4j_session,
            clusters_metadata,
            region,
            account_id,
            update_tag,
        )

        for cluster_metadata in clusters_metadata:
            _sync_ecs_container_instances(
                neo4j_session,
                cluster_metadata,
                region,
                account_id,
                update_tag,
            )

            _sync_ecs_task_and_container_defns(
                neo4j_session,
                cluster_metadata,
                region,
                account_id,
                update_tag,
            )

            _sync_ecs_services(
                neo4j_session,
                cluster_metadata,
                region,
                account_id,
                update_tag,
            )

    cartography_ecs.cleanup_ecs(neo4j_session, common_job_parameters)



def _sync_ecs_clusters(
    neo4j_session: neo4j.Session,
    clusters_metadata: list[dict[str, Any]],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_cluster_arns` and `cartography.intel.aws.ecs.get_ecs_clusters`.
    """

    clusters = []
    for cluster_metadata in clusters_metadata:
        clusters.append({
            "clusterArn": cluster_metadata.get("arn"),
            "clusterName": cluster_metadata.get("name"),
            # "configuration"  # TODO
            # "status"  # TODO
            # "registeredContainerInstancesCount"  # TODO
            # "pendingTasksCount"  # TODO
            "activeServicesCount": len(cluster_metadata.get("services")),
            "statistics": [],  # TODO
            "tags": cluster_metadata.get("tags"),
            "settings": cluster_metadata.get("settings"),
            "capacityProviders": [
                service.get("launch_type")
                for service in cluster_metadata.get("services").values()
                if service.get("launch_type")
                ],
            # "defaultCapacityProviderStrategy"  # TODO
        })

    cartography_ecs.load_ecs_clusters(
        neo4j_session,
        clusters,
        region,
        account_id,
        update_tag,
    )


def _sync_ecs_container_instances(
    neo4j_session: neo4j.Session,
    cluster_metadata: dict[str, Any],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_container_instances` and
    `cartography.intel.aws.ecs.get_ecs_container_instances`.
    """

    cluster_arn = cluster_metadata.get("arn")
    cluster_instances = []  # TODO

    cartography_ecs.load_ecs_container_instances(
        neo4j_session,
        cluster_arn,
        cluster_instances,
        region,
        account_id,
        update_tag,
    )


def _sync_ecs_task_and_container_defns(
    neo4j_session: neo4j.Session,
    cluster_metadata: dict[str, Any],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_task_and_container_defns` and
    # TODO
    """

    pass  # TODO


def _sync_ecs_services(
    neo4j_session: neo4j.Session,
    cluster_metadata: dict[str, Any],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_services` and
    # TODO
    """

    cluster_arn = cluster_metadata.get("arn")
    services = []  # TODO

    cartography_ecs.load_ecs_services(
        neo4j_session,
        cluster_arn,
        services,
        region,
        account_id,
        update_tag,
    )
