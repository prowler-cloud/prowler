import logging

import neo4j

from cartography.client.core.tx import run_write_query

# TODO: Use the right logger
logger = logging.getLogger(__name__)

INDEX_STATEMENTS = [
    "CREATE INDEX prowler_finding_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.id);",
    "CREATE INDEX prowler_finding_severity IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.severity);",
    "CREATE INDEX prowler_finding_check_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.check_id);",
]

# :ProwlerFinding properties
"""
"id"
"uid"

"inserted_at"
"updated_at"
"first_seen_at"

"scan_id"

"delta"
"status"
"status_extended"
"severity"
"check_id"
"check_metadata"

"muted"
"muted_reason"
"""


def create_indexes(neo4j_session: neo4j.Session) -> None:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.create_indexes.run`.
    """

    logger.info("Creating indexes for cartography node types.")
    for statement in INDEX_STATEMENTS:
        logger.debug("Executing statement: %s", statement)
        run_write_query(neo4j_session, statement)


def analysis(neo4j_session: neo4j.Session, provider_id: str) -> None:
    pass
