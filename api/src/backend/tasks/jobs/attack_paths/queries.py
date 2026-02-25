# Cypher query templates for Attack Paths operations
from tasks.jobs.attack_paths.config import (
    INTERNET_NODE_LABEL,
    PROWLER_FINDING_LABEL,
    PROVIDER_RESOURCE_LABEL,
)


def render_cypher_template(template: str, replacements: dict[str, str]) -> str:
    """
    Render a Cypher query template by replacing placeholders.

    Placeholders use `__DOUBLE_UNDERSCORE__` format to avoid conflicts
    with Cypher syntax.
    """
    query = template
    for placeholder, value in replacements.items():
        query = query.replace(placeholder, value)
    return query


# Findings queries (used by findings.py)
# ---------------------------------------

ADD_RESOURCE_LABEL_TEMPLATE = """
    MATCH (account:__ROOT_LABEL__ {id: $provider_uid})-->(r)
    WHERE NOT r:__ROOT_LABEL__ AND NOT r:__RESOURCE_LABEL__
    WITH r LIMIT $batch_size
    SET r:__RESOURCE_LABEL__:__DEPRECATED_RESOURCE_LABEL__
    RETURN COUNT(r) AS labeled_count
"""

INSERT_FINDING_TEMPLATE = f"""
    MATCH (account:__ROOT_NODE_LABEL__ {{id: $provider_uid}})
    UNWIND $findings_data AS finding_data

    OPTIONAL MATCH (account)-->(resource_by_uid:__RESOURCE_LABEL__)
        WHERE resource_by_uid.__NODE_UID_FIELD__ = finding_data.resource_uid
    WITH account, finding_data, resource_by_uid

    OPTIONAL MATCH (account)-->(resource_by_id:__RESOURCE_LABEL__)
        WHERE resource_by_uid IS NULL
            AND resource_by_id.id = finding_data.resource_uid
    WITH account, finding_data, COALESCE(resource_by_uid, resource_by_id) AS resource
        WHERE resource IS NOT NULL

    MERGE (finding:{PROWLER_FINDING_LABEL} {{id: finding_data.id}})
        ON CREATE SET
            finding.id = finding_data.id,
            finding.uid = finding_data.uid,
            finding.inserted_at = finding_data.inserted_at,
            finding.updated_at = finding_data.updated_at,
            finding.first_seen_at = finding_data.first_seen_at,
            finding.scan_id = finding_data.scan_id,
            finding.delta = finding_data.delta,
            finding.status = finding_data.status,
            finding.status_extended = finding_data.status_extended,
            finding.severity = finding_data.severity,
            finding.check_id = finding_data.check_id,
            finding.check_title = finding_data.check_title,
            finding.muted = finding_data.muted,
            finding.muted_reason = finding_data.muted_reason,
            finding.provider_uid = $provider_uid,
            finding.firstseen = timestamp(),
            finding.lastupdated = $last_updated,
            finding._module_name = 'cartography:prowler',
            finding._module_version = $prowler_version
        ON MATCH SET
            finding.status = finding_data.status,
            finding.status_extended = finding_data.status_extended,
            finding.lastupdated = $last_updated

    MERGE (resource)-[rel:HAS_FINDING]->(finding)
        ON CREATE SET
            rel.provider_uid = $provider_uid,
            rel.firstseen = timestamp(),
            rel.lastupdated = $last_updated,
            rel._module_name = 'cartography:prowler',
            rel._module_version = $prowler_version
        ON MATCH SET
            rel.lastupdated = $last_updated
"""

CLEANUP_FINDINGS_TEMPLATE = f"""
    MATCH (finding:{PROWLER_FINDING_LABEL} {{provider_uid: $provider_uid}})
        WHERE finding.lastupdated < $last_updated

    WITH finding LIMIT $batch_size

    DETACH DELETE finding

    RETURN COUNT(finding) AS deleted_findings_count
"""

# Internet queries (used by internet.py)
# ---------------------------------------

CREATE_INTERNET_NODE = f"""
    MERGE (internet:{INTERNET_NODE_LABEL} {{id: 'Internet'}})
    ON CREATE SET
        internet.name = 'Internet',
        internet.firstseen = timestamp(),
        internet.lastupdated = $last_updated,
        internet._module_name = 'cartography:prowler',
        internet._module_version = $prowler_version
    ON MATCH SET
        internet.lastupdated = $last_updated
"""

CREATE_CAN_ACCESS_RELATIONSHIPS_TEMPLATE = f"""
    MATCH (account:__ROOT_LABEL__ {{id: $provider_uid}})-->(resource)
    WHERE resource.exposed_internet = true
    WITH resource
    MATCH (internet:{INTERNET_NODE_LABEL} {{id: 'Internet'}})
    MERGE (internet)-[r:CAN_ACCESS]->(resource)
    ON CREATE SET
        r.firstseen = timestamp(),
        r.lastupdated = $last_updated,
        r._module_name = 'cartography:prowler',
        r._module_version = $prowler_version
    ON MATCH SET
        r.lastupdated = $last_updated
    RETURN COUNT(r) AS relationships_merged
"""

# Sync queries (used by sync.py)
# -------------------------------

NODE_FETCH_QUERY = """
    MATCH (n)
    WHERE id(n) > $last_id
    RETURN id(n) AS internal_id,
           elementId(n) AS element_id,
           labels(n) AS labels,
           properties(n) AS props
    ORDER BY internal_id
    LIMIT $batch_size
"""

RELATIONSHIPS_FETCH_QUERY = """
    MATCH ()-[r]->()
    WHERE id(r) > $last_id
    RETURN id(r) AS internal_id,
           type(r) AS rel_type,
           elementId(startNode(r)) AS start_element_id,
           elementId(endNode(r)) AS end_element_id,
           properties(r) AS props
    ORDER BY internal_id
    LIMIT $batch_size
"""

NODE_SYNC_TEMPLATE = """
    UNWIND $rows AS row
    MERGE (n:__NODE_LABELS__ {_provider_element_id: row.provider_element_id})
    SET n += row.props
    SET n._provider_id = $provider_id
    SET n.provider_element_id = row.provider_element_id
    SET n.provider_id = $provider_id
"""  # The last two lines are deprecated properties

RELATIONSHIP_SYNC_TEMPLATE = f"""
    UNWIND $rows AS row
    MATCH (s:{PROVIDER_RESOURCE_LABEL} {{_provider_element_id: row.start_element_id}})
    MATCH (t:{PROVIDER_RESOURCE_LABEL} {{_provider_element_id: row.end_element_id}})
    MERGE (s)-[r:__REL_TYPE__ {{_provider_element_id: row.provider_element_id}}]->(t)
    SET r += row.props
    SET r._provider_id = $provider_id
    SET r.provider_element_id = row.provider_element_id
    SET r.provider_id = $provider_id
"""  # The last two lines are deprecated properties
