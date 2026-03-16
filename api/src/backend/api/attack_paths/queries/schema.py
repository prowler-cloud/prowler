from tasks.jobs.attack_paths.config import PROVIDER_ID_PROPERTY, PROVIDER_RESOURCE_LABEL

CARTOGRAPHY_SCHEMA_METADATA = f"""
    MATCH (n:{PROVIDER_RESOURCE_LABEL} {{{PROVIDER_ID_PROPERTY}: $provider_id}})
    WHERE n._module_name STARTS WITH 'cartography:'
      AND NOT n._module_name IN ['cartography:ontology', 'cartography:prowler']
      AND n._module_version IS NOT NULL
    RETURN n._module_name AS module_name, n._module_version AS module_version
    LIMIT 1
"""

GITHUB_SCHEMA_URL = (
    "https://github.com/cartography-cncf/cartography/blob/"
    "{version}/docs/root/modules/{provider}/schema.md"
)
RAW_SCHEMA_URL = (
    "https://raw.githubusercontent.com/cartography-cncf/cartography/"
    "refs/tags/{version}/docs/root/modules/{provider}/schema.md"
)
