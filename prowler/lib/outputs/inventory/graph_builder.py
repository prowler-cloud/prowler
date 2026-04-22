"""
graph_builder.py
----------------
Builds a ConnectivityGraph by reading already-loaded AWS service clients from
sys.modules.  Only services that were actually scanned (i.e. whose client
module is already imported) contribute nodes and edges.  Unknown / unloaded
services are silently skipped, so the output degrades gracefully when only a
subset of checks has been run.
"""

import sys
from typing import Tuple

from prowler.lib.logger import logger
from prowler.lib.outputs.inventory.models import ConnectivityGraph

# Registry: (sys.modules key, attribute name inside that module, extractor module path)
_SERVICE_REGISTRY: Tuple[Tuple[str, str, str], ...] = (
    (
        "prowler.providers.aws.services.awslambda.awslambda_client",
        "awslambda_client",
        "prowler.lib.outputs.inventory.extractors.lambda_extractor",
    ),
    (
        "prowler.providers.aws.services.ec2.ec2_client",
        "ec2_client",
        "prowler.lib.outputs.inventory.extractors.ec2_extractor",
    ),
    (
        "prowler.providers.aws.services.vpc.vpc_client",
        "vpc_client",
        "prowler.lib.outputs.inventory.extractors.vpc_extractor",
    ),
    (
        "prowler.providers.aws.services.rds.rds_client",
        "rds_client",
        "prowler.lib.outputs.inventory.extractors.rds_extractor",
    ),
    (
        "prowler.providers.aws.services.elbv2.elbv2_client",
        "elbv2_client",
        "prowler.lib.outputs.inventory.extractors.elbv2_extractor",
    ),
    (
        "prowler.providers.aws.services.s3.s3_client",
        "s3_client",
        "prowler.lib.outputs.inventory.extractors.s3_extractor",
    ),
    (
        "prowler.providers.aws.services.iam.iam_client",
        "iam_client",
        "prowler.lib.outputs.inventory.extractors.iam_extractor",
    ),
)


def build_graph() -> ConnectivityGraph:
    """
    Iterate over every registered service, check whether its client module is
    already loaded, and call the corresponding extractor.

    Returns a ConnectivityGraph with all discovered nodes and edges.
    Duplicate node IDs are silently deduplicated (first occurrence wins).
    """
    graph = ConnectivityGraph()
    seen_node_ids: set = set()

    for client_module_key, client_attr, extractor_module_key in _SERVICE_REGISTRY:
        client_module = sys.modules.get(client_module_key)
        if client_module is None:
            continue

        service_client = getattr(client_module, client_attr, None)
        if service_client is None:
            continue

        extractor_module = sys.modules.get(extractor_module_key)
        if extractor_module is None:
            try:
                import importlib
                extractor_module = importlib.import_module(extractor_module_key)
            except ImportError as e:
                logger.debug(f"inventory graph_builder: cannot import extractor {extractor_module_key}: {e}")
                continue

        try:
            nodes, edges = extractor_module.extract(service_client)
        except Exception as e:
            logger.error(
                f"inventory graph_builder: extractor {extractor_module_key} failed: "
                f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
            )
            continue

        for node in nodes:
            if node.id not in seen_node_ids:
                graph.add_node(node)
                seen_node_ids.add(node.id)

        for edge in edges:
            graph.add_edge(edge)

    return graph
