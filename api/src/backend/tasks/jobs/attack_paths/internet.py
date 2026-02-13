"""
Internet node enrichment for Attack Paths graph.

Creates a real Internet node and CAN_ACCESS relationships to
internet-exposed resources (EC2Instance, LoadBalancer, LoadBalancerV2)
in the temporary scan database before sync.
"""

import neo4j

from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger

from api.models import Provider
from prowler.config import config as ProwlerConfig
from tasks.jobs.attack_paths.config import get_root_node_label
from tasks.jobs.attack_paths.queries import (
    CREATE_CAN_ACCESS_RELATIONSHIPS_TEMPLATE,
    CREATE_INTERNET_NODE,
    render_cypher_template,
)

logger = get_task_logger(__name__)


def analysis(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> int:
    """
    Create Internet node and CAN_ACCESS relationships to exposed resources.

    Args:
        neo4j_session: Active Neo4j session (temp database).
        prowler_api_provider: The Prowler API provider instance.
        config: Cartography configuration with update_tag.

    Returns:
        Number of CAN_ACCESS relationships created.
    """
    provider_uid = str(prowler_api_provider.uid)

    parameters = {
        "provider_uid": provider_uid,
        "last_updated": config.update_tag,
        "prowler_version": ProwlerConfig.prowler_version,
    }

    logger.info(f"Creating Internet node for provider {provider_uid}")
    neo4j_session.run(CREATE_INTERNET_NODE, parameters)

    query = render_cypher_template(
        CREATE_CAN_ACCESS_RELATIONSHIPS_TEMPLATE,
        {"__ROOT_LABEL__": get_root_node_label(prowler_api_provider.provider)},
    )

    logger.info(
        f"Creating CAN_ACCESS relationships from Internet to exposed resources for {provider_uid}"
    )
    result = neo4j_session.run(query, parameters)
    relationships_merged = result.single().get("relationships_merged", 0)

    logger.info(
        f"Created {relationships_merged} CAN_ACCESS relationships for provider {provider_uid}"
    )
    return relationships_merged
