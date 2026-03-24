---
name: prowler-attack-paths-query
description: >
  Creates Prowler Attack Paths openCypher queries using the Cartography schema as the source of truth
  for node labels, properties, and relationships. Also covers Prowler-specific additions (Internet node,
  ProwlerFinding, internal isolation labels) and $provider_uid scoping for predefined queries.
  Trigger: When creating or updating Attack Paths queries.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, api]
  auto_invoke:
    - "Creating Attack Paths queries"
    - "Updating existing Attack Paths queries"
    - "Adding privilege escalation detection queries"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, Task
---

## Overview

Attack Paths queries are openCypher queries that analyze cloud infrastructure graphs (ingested via Cartography) to detect security risks like privilege escalation paths, network exposure, and misconfigurations.

Queries are written in **openCypher Version 9** for compatibility with both Neo4j and Amazon Neptune.

---

## Two query audiences

This skill covers two types of queries with different isolation mechanisms:

| | Predefined queries | Custom queries |
|---|---|---|
| **Where they live** | `api/src/backend/api/attack_paths/queries/{provider}.py` | User/LLM-supplied via the custom query API endpoint |
| **Provider isolation** | `AWSAccount {id: $provider_uid}` anchor + path connectivity | Automatic `_Provider_{uuid}` label injection via `cypher_sanitizer.py` |
| **What to write** | Chain every MATCH from the `aws` variable | Plain Cypher, no isolation boilerplate needed |
| **Internal labels** | Never use (`_ProviderResource`, `_Tenant_*`, `_Provider_*`) | Never use (injected automatically by the system) |

**For predefined queries**: every node must be reachable from the `AWSAccount` root via graph traversal. This is the isolation boundary.

**For custom queries**: write natural Cypher without isolation concerns. The query runner injects a `_Provider_{uuid}` label into every node pattern before execution, and a post-query filter catches edge cases.

---

## Input Sources

Queries can be created from:

1. **pathfinding.cloud ID** (e.g., `ECS-001`, `GLUE-001`)
   - Reference: https://github.com/DataDog/pathfinding.cloud
   - The aggregated `paths.json` is too large for WebFetch. Use Bash:

   ```bash
   # Fetch a single path by ID
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq '.[] | select(.id == "ecs-002")'

   # List all path IDs and names
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq -r '.[] | "\(.id): \(.name)"'

   # Filter by service prefix
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq -r '.[] | select(.id | startswith("ecs")) | "\(.id): \(.name)"'
   ```

   If `jq` is not available, use `python3 -c "import json,sys; ..."` as a fallback.

2. **Natural language description** from the user

---

## Query Structure

### Provider scoping parameter

One parameter is injected automatically by the query runner:

| Parameter       | Property it matches | Used on      | Purpose                          |
| --------------- | ------------------- | ------------ | -------------------------------- |
| `$provider_uid` | `id`                | `AWSAccount` | Scopes to a specific AWS account |

All other nodes are isolated by path connectivity from the `AWSAccount` anchor.

### Imports

All query files start with these imports:

```python
from api.attack_paths.queries.types import (
    AttackPathsQueryAttribution,
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL
```

The `PROWLER_FINDING_LABEL` constant (value: `"ProwlerFinding"`) is used via f-string interpolation in all queries. Never hardcode the label string.

### Privilege escalation sub-patterns

There are four distinct privilege escalation patterns. Choose based on the attack type:

| Sub-pattern | Target | `path_target` shape | Example |
|---|---|---|---|
| Self-escalation | Principal's own policies | `(aws)--(target_policy:AWSPolicy)--(principal)` | IAM-001 |
| Lateral to user | Other IAM users | `(aws)--(target_user:AWSUser)` | IAM-002 |
| Assume-role lateral | Assumable roles | `(aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)` | IAM-014 |
| PassRole + service | Service-trusting roles | `(aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(...)` | EC2-001 |

#### Self-escalation (e.g., IAM-001)

The principal modifies resources attached to itself. `path_target` loops back to `principal`:

```python
AWS_{QUERY_NAME} = AttackPathsQueryDefinition(
    id="aws-{kebab-case-name}",
    name="{Human-friendly label} ({REFERENCE_ID})",
    short_description="{Brief explanation, no technical permissions.}",
    description="{Detailed description of the attack vector and impact.}",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - {REFERENCE_ID} - {permission}",
        link="https://pathfinding.cloud/paths/{reference_id_lowercase}",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with {permission}
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = '{permission_lowercase}'
                OR toLower(action) = '{service}:*'
                OR action = '*'
            )

        // Find target resources attached to the same principal
        MATCH path_target = (aws)--(target_policy:AWSPolicy)--(principal)
        WHERE target_policy.arn CONTAINS $provider_uid
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR target_policy.arn CONTAINS resource
            )

        WITH collect(path_principal) + collect(path_target) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)
```

#### Other sub-pattern `path_target` shapes

The other 3 sub-patterns share the same `path_principal`, deduplication tail, and RETURN as self-escalation. Only the `path_target` MATCH differs:

```cypher
// Lateral to user (e.g., IAM-002) - targets other IAM users
MATCH path_target = (aws)--(target_user:AWSUser)
WHERE any(resource IN stmt.resource WHERE resource = '*' OR target_user.arn CONTAINS resource OR resource CONTAINS target_user.name)

// Assume-role lateral (e.g., IAM-014) - targets roles the principal can assume
MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
WHERE any(resource IN stmt.resource WHERE resource = '*' OR target_role.arn CONTAINS resource OR resource CONTAINS target_role.name)

// PassRole + service (e.g., EC2-001) - targets roles trusting a service
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: '{service}.amazonaws.com'})
WHERE any(resource IN stmt.resource WHERE resource = '*' OR target_role.arn CONTAINS resource OR resource CONTAINS target_role.name)
```

**Multi-permission**: PassRole queries require a second permission. Add `MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)` with its own WHERE before `path_target`, then check BOTH `stmt.resource` AND `stmt2.resource` against the target. See IAM-015 or EC2-001 in `aws.py` for examples.

### Network exposure pattern

The Internet node is reached via `CAN_ACCESS` through the already-scoped resource, not via a standalone lookup:

```python
AWS_{QUERY_NAME} = AttackPathsQueryDefinition(
    id="aws-{kebab-case-name}",
    name="{Human-friendly label}",
    short_description="{Brief explanation.}",
    description="{Detailed description.}",
    provider="aws",
    cypher=f"""
        // Match exposed resources (MUST chain from `aws`)
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(resource:EC2Instance)
        WHERE resource.exposed_internet = true

        // Internet node reached via path connectivity through the resource
        OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(resource)

        WITH collect(path) AS paths, head(collect(internet)) AS internet, collect(can_access) AS can_access
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, internet, can_access, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
            internet, can_access
    """,
    parameters=[],
)
```

### Register in query list

Add to the `{PROVIDER}_QUERIES` list at the bottom of the file:

```python
AWS_QUERIES: list[AttackPathsQueryDefinition] = [
    # ... existing queries ...
    AWS_{NEW_QUERY_NAME},  # Add here
]
```

---

## Step-by-step creation process

### 1. Read the queries module

**FIRST**, read all files in the queries module to understand the structure, type definitions, registration, and existing style:

```
api/src/backend/api/attack_paths/queries/
├── __init__.py      # Module exports
├── types.py         # AttackPathsQueryDefinition, AttackPathsQueryParameterDefinition
├── registry.py      # Query registry logic
└── {provider}.py    # Provider-specific queries (e.g., aws.py)
```

**DO NOT** use generic templates. Match the exact style of existing queries in the file.

### 2. Fetch and consult the Cartography schema

**This is the most important step.** Every node label, property, and relationship in the query must exist in the Cartography schema for the pinned version. Do not guess or rely on memory.

Check `api/pyproject.toml` for the Cartography dependency, then fetch the schema:

```bash
grep cartography api/pyproject.toml
```

Build the schema URL (ALWAYS use the specific tag, not master/main):

```
# Git dependency (prowler-cloud/cartography@0.126.1):
https://raw.githubusercontent.com/prowler-cloud/cartography/refs/tags/0.126.1/docs/root/modules/{provider}/schema.md

# PyPI dependency (cartography = "^0.126.0"):
https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/0.126.0/docs/root/modules/{provider}/schema.md
```

Read the schema to discover available node labels, properties, and relationships for the target resources. Internal labels (`_ProviderResource`, `_AWSResource`, `_Tenant_*`, `_Provider_*`) exist for isolation but should never appear in queries.

### 4. Create query definition

Use the appropriate pattern (privilege escalation or network exposure) with:

- **id**: `{provider}-{kebab-case-description}`
- **name**: Short, human-friendly label. For sourced queries, append the reference ID: `"EC2 Instance Launch with Privileged Role (EC2-001)"`.
- **short_description**: Brief explanation, no technical permissions.
- **description**: Full technical explanation. Plain text only.
- **provider**: Provider identifier (aws, azure, gcp, kubernetes, github)
- **cypher**: The openCypher query with proper escaping
- **parameters**: Optional list of user-provided parameters (`parameters=[]` if none)
- **attribution**: Optional `AttackPathsQueryAttribution(text, link)` for sourced queries. The `text` includes source, reference ID, and permissions. The `link` uses a lowercase ID. Omit for non-sourced queries.

### 5. Add query to provider list

Add the constant to the `{PROVIDER}_QUERIES` list.

---

## Query naming conventions

### Query ID

```
{provider}-{category}-{description}
```

Examples: `aws-ec2-privesc-passrole-iam`, `aws-ec2-instances-internet-exposed`

### Query constant name

```
{PROVIDER}_{CATEGORY}_{DESCRIPTION}
```

Examples: `AWS_EC2_PRIVESC_PASSROLE_IAM`, `AWS_EC2_INSTANCES_INTERNET_EXPOSED`

---

## Query categories

| Category             | Description                    | Example                   |
| -------------------- | ------------------------------ | ------------------------- |
| Basic Resource       | List resources with properties | RDS instances, S3 buckets |
| Network Exposure     | Internet-exposed resources     | EC2 with public IPs       |
| Privilege Escalation | IAM privilege escalation paths | PassRole + RunInstances   |
| Data Access          | Access to sensitive data       | EC2 with S3 access        |

---

## Common openCypher patterns

### Match account and principal

```cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
```

### Check IAM action permissions

```cypher
WHERE stmt.effect = 'Allow'
    AND any(action IN stmt.action WHERE
        toLower(action) = 'iam:passrole'
        OR toLower(action) = 'iam:*'
        OR action = '*'
    )
```

### Find roles trusting a service

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: 'ec2.amazonaws.com'})
```

### Find roles the principal can assume

Note the arrow direction - `STS_ASSUMEROLE_ALLOW` points from the role to the principal:

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
```

### Check resource scope

```cypher
WHERE any(resource IN stmt.resource WHERE
    resource = '*'
    OR target_role.arn CONTAINS resource
    OR resource CONTAINS target_role.name
)
```

### Internet node via path connectivity

The Internet node is reached through `CAN_ACCESS` relationships to already-scoped resources. No standalone lookup needed:

```cypher
OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(resource)
```

### Multi-label OR (match multiple resource types)

```cypher
MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x)-[q]-(y)
WHERE (x:EC2PrivateIp AND x.public_ip = $ip)
   OR (x:EC2Instance AND x.publicipaddress = $ip)
   OR (x:NetworkInterface AND x.public_ip = $ip)
   OR (x:ElasticIPAddress AND x.public_ip = $ip)
```

### Include Prowler findings

Deduplicate nodes before the ProwlerFinding lookup to avoid redundant OPTIONAL MATCH calls on nodes that appear in multiple paths:

```cypher
WITH collect(path_principal) + collect(path_target) AS paths
UNWIND paths AS p
UNWIND nodes(p) AS n

WITH paths, collect(DISTINCT n) AS unique_nodes
UNWIND unique_nodes AS n
OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
```

For network exposure queries, aggregate the internet node and relationship alongside paths:

```cypher
WITH collect(path) AS paths, head(collect(internet)) AS internet, collect(can_access) AS can_access
UNWIND paths AS p
UNWIND nodes(p) AS n

WITH paths, internet, can_access, collect(DISTINCT n) AS unique_nodes
UNWIND unique_nodes AS n
OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
    internet, can_access
```

---

## Prowler-specific labels and relationships

These are added by the sync task, not part of the Cartography schema. For all other node labels, properties, and relationships, **always consult the Cartography schema** (see step 2 below).

| Label/Relationship     | Description                                        |
| ---------------------- | -------------------------------------------------- |
| `ProwlerFinding`       | Finding node (`status`, `severity`, `check_id`)    |
| `Internet`             | Internet sentinel node                             |
| `CAN_ACCESS`           | Internet-to-resource exposure (relationship)       |
| `HAS_FINDING`          | Resource-to-finding link (relationship)            |
| `TRUSTS_AWS_PRINCIPAL` | Role trust relationship                            |
| `STS_ASSUMEROLE_ALLOW` | Can assume role (direction: role -> principal)      |

---

## Parameters

For queries requiring user input:

```python
parameters=[
    AttackPathsQueryParameterDefinition(
        name="ip",
        label="IP address",
        # data_type defaults to "string", cast defaults to str.
        # For non-string params, set both: data_type="integer", cast=int
        description="Public IP address, e.g. 192.0.2.0.",
        placeholder="192.0.2.0",
    ),
],
```

---

## Best practices

1. **Chain all MATCHes from the root account node**: Every `MATCH` clause must connect to the `aws` variable (or another variable already bound to the account's subgraph). An unanchored `MATCH` would return nodes from all providers.

   ```cypher
   // WRONG: matches ALL AWSRoles across all providers
   MATCH (role:AWSRole) WHERE role.name = 'admin'

   // CORRECT: scoped to the specific account's subgraph
   MATCH (aws)--(role:AWSRole) WHERE role.name = 'admin'
   ```

   **Exception**: A second-permission MATCH like `MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)` is safe because `principal` is already bound to the account's subgraph by the first MATCH. It does not need to chain from `aws` again.

2. **Include Prowler findings**: Always add `OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})` with `collect(DISTINCT pf)`.

3. **Comment the query purpose**: Add inline comments explaining each MATCH clause.

4. **Never use internal labels in queries**: `_ProviderResource`, `_AWSResource`, `_Tenant_*`, `_Provider_*` are for system isolation. They should never appear in predefined or custom query text.

6. **Internet node uses path connectivity**: Reach it via `OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(resource)` where `resource` is already scoped by the account anchor. No standalone lookup.

---

## openCypher compatibility

Queries must be written in **openCypher Version 9** for compatibility with both Neo4j and Amazon Neptune.

### Avoid these (not in openCypher spec)

| Feature                    | Use instead                                            |
| -------------------------- | ------------------------------------------------------ |
| APOC procedures (`apoc.*`) | Real nodes and relationships in the graph              |
| Neptune extensions         | Standard openCypher                                    |
| `reduce()` function        | `UNWIND` + `collect()`                                 |
| `FOREACH` clause           | `WITH` + `UNWIND` + `SET`                              |
| Regex operator (`=~`)      | `toLower()` + exact match, or `CONTAINS`/`STARTS WITH`. One legacy query uses `=~` - do not add new usages |
| `CALL () { UNION }`        | Multi-label OR in WHERE (see patterns section)         |

---

## Reference

- **pathfinding.cloud**: https://github.com/DataDog/pathfinding.cloud (use `curl | jq`, not WebFetch)
- **Cartography schema**: `https://raw.githubusercontent.com/{org}/cartography/refs/tags/{version}/docs/root/modules/{provider}/schema.md`
- **Neptune openCypher compliance**: https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html
- **openCypher spec**: https://github.com/opencypher/openCypher
