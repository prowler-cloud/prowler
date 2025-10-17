from asyncio import tasks
import json

from collections import defaultdict
from typing import Any

from httpx import get
import neo4j

from cartography.intel.aws import ecs as cartography_ecs
from celery.utils.log import get_task_logger
from openai import containers

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
    tasks_region_cluster_metadata = _get_ecs_tasks_region_cluster_metadata(tenant_id, provider_id, scan_id, regions)

    # Calling our version of cartography AWS ECS sync
    return _sync(
        neo4j_session,
        account_id,
        clusters_region_metadata,
        tasks_region_cluster_metadata,
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
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="ecs",
                resource_type="AwsEcsCluster",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    clusters_region_metadata = defaultdict(list)
    for cluster in clusters_qs:
        cluster_metadata = json.loads(cluster.metadata)
        cluster_metadata["inserted_at"] = cluster.inserted_at
        clusters_region_metadata[cluster_metadata.get("region")].append(cluster_metadata)

    return clusters_region_metadata


def _get_ecs_tasks_region_cluster_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """
    Getting ECS tasks metadata from Prowler DB.
    # TODO: We can't filter the tasks by cluster ARN using Prowler data
    """

    with rls_transaction(tenant_id):
        tasks_qs = Resource.objects.filter(
            provider_id=provider_id,
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="ecs",
                resource_type="AwsEcsTaskDefinition",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    tasks_region_cluster_metadata = defaultdict(defaultdict(list))
    for task in tasks_qs:
        task_metadata = json.loads(task.metadata)
        task_metadata["inserted_at"] = task.inserted_at
        tasks_region_cluster_metadata[
            task_metadata.get("region")
        ][
            task_metadata.get("cluster_arn")  # TODO: We can't filter the tasks by cluster ARN using Prowler data
        ].append(task_metadata)

    return tasks_region_cluster_metadata


def _sync(
    neo4j_session: neo4j.Session,
    account_id: str,
    clusters_region_metadata: dict[str, list[dict[str, Any]]],
    tasks_region_cluster_metadata: dict[str, dict[str, list[dict[str, Any]]]],
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Code based on `cartography.intel.aws.ecs.sync`.
    """

    for region in clusters_region_metadata.keys():
        clusters_metadata = clusters_region_metadata.get(region)
        tasks_cluster_metadata = tasks_region_cluster_metadata.get(region, {})

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

            for cluster in tasks_cluster_metadata.keys():
                tasks_metadata = tasks_cluster_metadata.get(cluster, [])

                _sync_ecs_task_and_container_defns(
                    neo4j_session,
                    clusters_metadata,
                    tasks_metadata,
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
    Code based on `cartography.intel.aws.ecs._sync_ecs_cluster_arns` and
    `cartography.intel.aws.ecs.get_ecs_clusters`.
    # TODO: There are missing fields to implement
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
            "activeServicesCount": len(cluster_metadata.get("services")),  # TODO: Check if this is correct
            # "statistics"  # TODO
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
    # TODO: Container instances data is missing from Prowler DB
    """

    cluster_arn = cluster_metadata.get("arn")
    containers_instances = []  # TODO

    cartography_ecs.load_ecs_container_instances(
        neo4j_session,
        cluster_arn,
        containers_instances,
        region,
        account_id,
        update_tag,
    )


def _sync_ecs_task_and_container_defns(
    neo4j_session: neo4j.Session,
    cluster_metadata: dict[str, Any],
    tasks_metadata: dict[str, Any],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_task_and_container_defns`,
    `cartography.intel.aws.ecs.get_ecs_tasks`, `cartography.intel.aws.ecs.transform_ecs_tasks`,
    `cartography.intel.aws.ecs._get_containers_from_tasks`, `cartography.intel.aws.ecs.get_ecs_task_definitions`
    and `cartography.intel.aws.ecs._get_container_defs_from_task_definitions`.
    # TODO: Not implemented yet because with Prowler data we can't know the cluster ARN of a task
    """

    cluster_arn = cluster_metadata.get("arn")
    tasks = []
    containers = []  # From `tasks`
    task_definitions = []  # From `tasks`
    container_defs = []  # From `task_definitions`

    cartography_ecs.load_ecs_tasks(
        neo4j_session,
        cluster_arn,
        tasks,
        region,
        account_id,
        update_tag,
    )

    cartography_ecs.load_ecs_containers(
        neo4j_session,
        containers,
        region,
        account_id,
        update_tag,
    )

    cartography_ecs.load_ecs_task_definitions(
        neo4j_session,
        task_definitions,
        region,
        account_id,
        update_tag,
    )

    cartography_ecs.load_ecs_container_definitions(
        neo4j_session,
        container_defs,
        region,
        account_id,
        update_tag,
    )


def _sync_ecs_services(
    neo4j_session: neo4j.Session,
    cluster_metadata: dict[str, Any],
    region: str,
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.ecs._sync_ecs_services` and
    `cartography.intel.aws.ecs.get_ecs_services`.
    # TODO: A lot of fields are missing and probably some of them are too important
    """

    cluster_arn = cluster_metadata.get("arn")
    services = [
        {
            "serviceArn": service.get("arn"),
            "serviceName": service.get("name"),
            "clusterArn": cluster_arn,
            # "loadBalancers"  # TODO
            # "serviceRegistries"  # TODO
            # "status"  # TODO
            # "desiredCount": # TODO
            # "runningCount": # TODO
            "launcType": service.get("launch_type"),
            "platformVersion": service.get("platform_version"),
            "platformFamily": service.get("platform_family"),
            # "taskDefinition"  # TODO
            # "deploymentConfiguration"
            # "deployments"
            # "roleArn"  # TODO: Important?
            # "events"
            "createdAt": cluster_metadata.get("inserted_at"),
            # "placementConstraints"  # TODO
            # "placementStrategy"  # TODO
            # "networkConfiguration"  # TODO
            # "healthCheckGracePeriodSeconds"  # TODO
            # "schedulingStrategy"  # TODO
            # "deploymentController"  # TODO
            # "createdBy"  # TODO: Important?
            # "enableECSManagedTags"  # TODO
            # "propagateTags"  # TODO
            # "enableExecuteCommand"  # TODO
            # "availabilityZoneRebalancing"  # TODO
        }
        for service in cluster_metadata.get("services").values()
    ]

    cartography_ecs.load_ecs_services(
        neo4j_session,
        cluster_arn,
        services,
        region,
        account_id,
        update_tag,
    )
