---
name: prowler-attack-paths-query
description: >
  Creates Prowler Attack Paths openCypher queries for graph analysis (compatible with Neo4j and Neptune).
  Trigger: When creating or updating Attack Paths queries that detect privilege escalation paths,
  network exposure, or security misconfigurations in cloud environments.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, api]
  auto_invoke:
    - "Creating Attack Paths queries"
    - "Updating existing Attack Paths queries"
    - "Adding privilege escalation detection queries"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, Task
---

## Overview

Attack Paths queries are openCypher queries that analyze cloud infrastructure graphs (ingested via Cartography) to detect security risks like privilege escalation paths, network exposure, and misconfigurations.

Queries are written in **openCypher Version 9** to ensure compatibility with both Neo4j and Amazon Neptune.

---

## Input Sources

Queries can be created from:

1. **pathfinding.cloud ID** (e.g., `ECS-001`, `GLUE-001`)
   - The JSON index contains: `id`, `name`, `description`, `services`, `permissions`, `exploitationSteps`, `prerequisites`, etc.
   - Reference: https://github.com/DataDog/pathfinding.cloud

   **Fetching a single path by ID** - The aggregated `paths.json` is too large for WebFetch
   (content gets truncated). Use Bash with `curl` and a JSON parser instead:

   Prefer `jq` (concise), fall back to `python3` (guaranteed in this Python project):

   ```bash
   # With jq
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq '.[] | select(.id == "ecs-002")'

   # With python3 (fallback)
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | python3 -c "import json,sys; print(json.dumps(next((p for p in json.load(sys.stdin) if p['id']=='ecs-002'), None), indent=2))"
   ```

2. **Listing Available Attack Paths**
   - Use Bash to list available paths from the JSON index:

   ```bash
   # List all path IDs and names (jq)
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq -r '.[] | "\(.id): \(.name)"'

   # List all path IDs and names (python3 fallback)
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | python3 -c "import json,sys; [print(f\"{p['id']}: {p['name']}\") for p in json.load(sys.stdin)]"

   # List paths filtered by service prefix
   curl -s https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json \
     | jq -r '.[] | select(.id | startswith("ecs")) | "\(.id): \(.name)"'
   ```

3. **Natural Language Description**
   - User describes the Attack Paths in plain language
   - Agent maps to appropriate openCypher patterns

---

## Query Structure

### File Location

```
api/src/backend/api/attack_paths/queries/{provider}.py
```

Example: `api/src/backend/api/attack_paths/queries/aws.py`

### Query parameters for provider scoping

Two parameters exist. Both are injected automatically by the query runner.

| Parameter       | Property it matches | Used on        | Purpose                              |
| --------------- | ------------------- | -------------- | ------------------------------------ |
| `$provider_uid` | `id`                | `AWSAccount`   | Scopes to a specific AWS account     |
| `$provider_id`  | `_provider_id`      | Any other node | Scopes nodes to the provider context |

### Privilege Escalation Query Pattern

```python
from api.attack_paths.queries.types import (
    AttackPathsQueryAttribution,
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)

# {REFERENCE_ID} (e.g., EC2-001, GLUE-001)
AWS_{QUERY_NAME} = AttackPathsQueryDefinition(
    id="aws-{kebab-case-name}",
    name="{Human-friendly label} ({REFERENCE_ID})",
    short_description="{Brief explanation of the attack, no technical permissions.}",
    description="{Detailed description of the attack vector and impact.}",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - {REFERENCE_ID} - {permission1} + {permission2}",
        link="https://pathfinding.cloud/paths/{reference_id_lowercase}",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with {permission1}
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = '{permission1_lowercase}'
                OR toLower(action) = '{service}:*'
                OR action = '*'
            )

        // Find {permission2}
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = '{permission2_lowercase}'
                OR toLower(action) = '{service2}:*'
                OR action = '*'
            )

        // Find target resources (MUST chain from `aws` for provider isolation)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: '{service}.amazonaws.com'}})
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)
```

### Network Exposure Query Pattern

```python
AWS_{QUERY_NAME} = AttackPathsQueryDefinition(
    id="aws-{kebab-case-name}",
    name="{Human-friendly label}",
    short_description="{Brief explanation.}",
    description="{Detailed description.}",
    provider="aws",
    cypher=f"""
        // Match the Internet sentinel node
        OPTIONAL MATCH (internet:Internet {{_provider_id: $provider_id}})

        // Match exposed resources (MUST chain from `aws`)
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(resource:EC2Instance)
        WHERE resource.exposed_internet = true

        // Link Internet to resource
        OPTIONAL MATCH (internet)-[can_access:CAN_ACCESS]->(resource)

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
            internet, can_access
    """,
    parameters=[],
)
```

### Register in Query List

Add to the `{PROVIDER}_QUERIES` list at the bottom of the file:

```python
AWS_QUERIES: list[AttackPathsQueryDefinition] = [
    # ... existing queries ...
    AWS_{NEW_QUERY_NAME},  # Add here
]
```

---

## Step-by-Step Creation Process

### 1. Read the Queries Module

**FIRST**, read all files in the queries module to understand the structure:

```
api/src/backend/api/attack_paths/queries/
├── __init__.py      # Module exports
├── types.py         # AttackPathsQueryDefinition, AttackPathsQueryParameterDefinition
├── registry.py      # Query registry logic
└── {provider}.py    # Provider-specific queries (e.g., aws.py)
```

Read these files to learn:

- Type definitions and available fields
- How queries are registered
- Current query patterns, style, and naming conventions

### 2. Determine Schema Source

Check the Cartography dependency in `api/pyproject.toml`:

```bash
grep cartography api/pyproject.toml
```

Parse the dependency to determine the schema source:

**If git-based dependency** (e.g., `cartography @ git+https://github.com/prowler-cloud/cartography@0.126.1`):

- Extract the repository (e.g., `prowler-cloud/cartography`)
- Extract the version/tag (e.g., `0.126.1`)
- Fetch schema from that repository at that tag

**If PyPI dependency** (e.g., `cartography = "^0.126.0"` or `cartography>=0.126.0`):

- Extract the version (e.g., `0.126.0`)
- Use the official `cartography-cncf` repository

**Schema URL patterns** (ALWAYS use the specific version tag, not master/main):

```
# Official Cartography (cartography-cncf)
https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/{version}/docs/root/modules/{provider}/schema.md

# Prowler fork (prowler-cloud)
https://raw.githubusercontent.com/prowler-cloud/cartography/refs/tags/{version}/docs/root/modules/{provider}/schema.md
```

**Examples**:

```bash
# For prowler-cloud/cartography@0.126.1 (git), fetch AWS schema:
https://raw.githubusercontent.com/prowler-cloud/cartography/refs/tags/0.126.1/docs/root/modules/aws/schema.md

# For cartography = "^0.126.0" (PyPI), fetch AWS schema:
https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/0.126.0/docs/root/modules/aws/schema.md
```

**IMPORTANT**: Always match the schema version to the dependency version in `pyproject.toml`. Using master/main may reference node labels or properties that don't exist in the deployed version.

**Additional Prowler Labels**: The Attack Paths sync task adds labels that queries can reference:

- `ProwlerFinding` - Prowler finding nodes with `status`, `provider_uid` properties
- `Internet` - Internet sentinel node with `_provider_id` property (used in network exposure queries)

Other internal labels (`_ProviderResource`, `_AWSResource`, `_Tenant_*`, `_Provider_*`) exist for isolation but should never be used in queries.

These are defined in `api/src/backend/tasks/jobs/attack_paths/config.py`.

### 3. Consult the Schema for Available Data

Use the Cartography schema to discover:

- What node labels exist for the target resources
- What properties are available on those nodes
- What relationships connect the nodes

This informs query design by showing what data is actually available to query.

### 4. Create Query Definition

Use the appropriate pattern (privilege escalation or network exposure) with:

- **id**: Auto-generated as `{provider}-{kebab-case-description}`
- **name**: Short, human-friendly label. No raw IAM permissions. For sourced queries (e.g., pathfinding.cloud), append the reference ID in parentheses: `"EC2 Instance Launch with Privileged Role (EC2-001)"`. If the name already has parentheses, prepend the ID inside them: `"ECS Service Creation with Privileged Role (ECS-003 - Existing Cluster)"`.
- **short_description**: Brief explanation of the attack, no technical permissions. E.g., "Launch EC2 instances with privileged IAM roles to gain their permissions via IMDS."
- **description**: Full technical explanation of the attack vector and impact. Plain text only, no HTML or technical permissions here.
- **provider**: Provider identifier (aws, azure, gcp, kubernetes, github)
- **cypher**: The openCypher query with proper escaping
- **parameters**: Optional list of user-provided parameters (use `parameters=[]` if none needed)
- **attribution**: Optional `AttackPathsQueryAttribution(text, link)` for sourced queries. The `text` includes the source, reference ID, and technical permissions (e.g., `"pathfinding.cloud - EC2-001 - iam:PassRole + ec2:RunInstances"`). The `link` is the URL with a lowercase ID (e.g., `"https://pathfinding.cloud/paths/ec2-001"`). Omit (defaults to `None`) for non-sourced queries.

### 5. Add Query to Provider List

Add the constant to the `{PROVIDER}_QUERIES` list.

---

## Query Naming Conventions

### Query ID

```
{provider}-{category}-{description}
```

Examples:

- `aws-ec2-privesc-passrole-iam`
- `aws-iam-privesc-attach-role-policy-assume-role`
- `aws-ec2-instances-internet-exposed`

### Query Constant Name

```
{PROVIDER}_{CATEGORY}_{DESCRIPTION}
```

Examples:

- `AWS_EC2_PRIVESC_PASSROLE_IAM`
- `AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_ASSUME_ROLE`
- `AWS_EC2_INSTANCES_INTERNET_EXPOSED`

---

## Query Categories

| Category             | Description                    | Example                   |
| -------------------- | ------------------------------ | ------------------------- |
| Basic Resource       | List resources with properties | RDS instances, S3 buckets |
| Network Exposure     | Internet-exposed resources     | EC2 with public IPs       |
| Privilege Escalation | IAM privilege escalation paths | PassRole + RunInstances   |
| Data Access          | Access to sensitive data       | EC2 with S3 access        |

---

## Common openCypher Patterns

### Match Account and Principal

```cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
```

### Check IAM Action Permissions

```cypher
WHERE stmt.effect = 'Allow'
    AND any(action IN stmt.action WHERE
        toLower(action) = 'iam:passrole'
        OR toLower(action) = 'iam:*'
        OR action = '*'
    )
```

### Find Roles Trusting a Service

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: 'ec2.amazonaws.com'})
```

### Check Resource Scope

```cypher
WHERE any(resource IN stmt.resource WHERE
    resource = '*'
    OR target_role.arn CONTAINS resource
    OR resource CONTAINS target_role.name
)
```

### Match Internet Sentinel Node

Used in network exposure queries. The Internet node is a real graph node, scoped by `_provider_id`:

```cypher
OPTIONAL MATCH (internet:Internet {_provider_id: $provider_id})
```

### Link Internet to Exposed Resource

The `CAN_ACCESS` relationship is a real graph relationship linking the Internet node to exposed resources:

```cypher
OPTIONAL MATCH (internet)-[can_access:CAN_ACCESS]->(resource)
```

### Multi-label OR (match multiple resource types)

When a query needs to match different resource types in the same position, use label checks in WHERE:

```cypher
MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x)-[q]-(y)
WHERE (x:EC2PrivateIp AND x.public_ip = $ip)
   OR (x:EC2Instance AND x.publicipaddress = $ip)
   OR (x:NetworkInterface AND x.public_ip = $ip)
   OR (x:ElasticIPAddress AND x.public_ip = $ip)
```

### Include Prowler Findings

```cypher
UNWIND nodes(path_principal) + nodes(path_target) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path_principal, path_target,
    collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
```

For network exposure queries, also return the internet node and relationship:

```cypher
RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
    internet, can_access
```

---

## Common Node Labels by Provider

### AWS

| Label                 | Description                             |
| --------------------- | --------------------------------------- |
| `AWSAccount`          | AWS account root                        |
| `AWSPrincipal`        | IAM principal (user, role, service)     |
| `AWSRole`             | IAM role                                |
| `AWSUser`             | IAM user                                |
| `AWSPolicy`           | IAM policy                              |
| `AWSPolicyStatement`  | Policy statement                        |
| `AWSTag`              | Resource tag (key/value)                |
| `EC2Instance`         | EC2 instance                            |
| `EC2SecurityGroup`    | Security group                          |
| `EC2PrivateIp`        | EC2 private IP (has `public_ip`)        |
| `IpPermissionInbound` | Inbound security group rule             |
| `IpRange`             | IP range (e.g., `0.0.0.0/0`)            |
| `NetworkInterface`    | ENI (has `public_ip`)                   |
| `ElasticIPAddress`    | Elastic IP (has `public_ip`)            |
| `S3Bucket`            | S3 bucket                               |
| `RDSInstance`         | RDS database instance                   |
| `LoadBalancer`        | Classic ELB                             |
| `LoadBalancerV2`      | ALB/NLB                                 |
| `ELBListener`         | Classic ELB listener                    |
| `ELBV2Listener`       | ALB/NLB listener                        |
| `LaunchTemplate`      | EC2 launch template                     |
| `Internet`            | Internet sentinel node (`_provider_id`) |

### Common Relationships

| Relationship           | Description                        |
| ---------------------- | ---------------------------------- |
| `TRUSTS_AWS_PRINCIPAL` | Role trust relationship            |
| `STS_ASSUMEROLE_ALLOW` | Can assume role                    |
| `CAN_ACCESS`           | Internet-to-resource exposure link |
| `POLICY`               | Has policy attached                |
| `STATEMENT`            | Policy has statement               |

---

## Parameters

For queries requiring user input, define parameters:

```python
parameters=[
    AttackPathsQueryParameterDefinition(
        name="ip",
        label="IP address",
        description="Public IP address, e.g. 192.0.2.0.",
        placeholder="192.0.2.0",
    ),
    AttackPathsQueryParameterDefinition(
        name="tag_key",
        label="Tag key",
        description="Tag key to filter resources.",
        placeholder="Environment",
    ),
],
```

---

## Best Practices

1. **Always scope by provider**: Use `{id: $provider_uid}` on `AWSAccount` nodes. Use `{_provider_id: $provider_id}` on any other node that needs provider scoping (e.g., `Internet`).

2. **Use consistent naming**: Follow existing patterns in the file

3. **Include Prowler findings**: Always add the OPTIONAL MATCH for ProwlerFinding nodes

4. **Return distinct findings**: Use `collect(DISTINCT pf)` to avoid duplicates

5. **Comment the query purpose**: Add inline comments explaining each MATCH clause

6. **Validate schema first**: Ensure all node labels and properties exist in Cartography schema

7. **Chain all MATCHes from the root account node**: Every `MATCH` clause must connect to the `aws` variable (or another variable already bound to the account's subgraph). The tenant database contains data from multiple providers — an unanchored `MATCH` would return nodes from all providers, breaking provider isolation.

   ```cypher
   // WRONG: matches ALL AWSRoles across all providers in the tenant DB
   MATCH (role:AWSRole) WHERE role.name = 'admin'

   // CORRECT: scoped to the specific account's subgraph
   MATCH (aws)--(role:AWSRole) WHERE role.name = 'admin'
   ```

   The `Internet` node is an exception: it uses `OPTIONAL MATCH` with `_provider_id` for scoping instead of chaining from `aws`.

---

## openCypher Compatibility

Queries must be written in **openCypher Version 9** to ensure compatibility with both Neo4j and Amazon Neptune.

> **Why Version 9?** Amazon Neptune implements openCypher Version 9. By targeting this specification, queries work on both Neo4j and Neptune without modification.

### Avoid These (Not in openCypher spec)

| Feature                    | Reason                                          | Use instead                                            |
| -------------------------- | ----------------------------------------------- | ------------------------------------------------------ |
| APOC procedures (`apoc.*`) | Neo4j-specific plugin, not available in Neptune | Real nodes and relationships in the graph              |
| Neptune extensions         | Not available in Neo4j                          | Standard openCypher                                    |
| `reduce()` function        | Not in openCypher spec                          | `UNWIND` + `collect()`                                 |
| `FOREACH` clause           | Not in openCypher spec                          | `WITH` + `UNWIND` + `SET`                              |
| Regex operator (`=~`)      | Not supported in Neptune                        | `toLower()` + exact match, or `CONTAINS`/`STARTS WITH` |
| `CALL () { UNION }`        | Complex, hard to maintain                       | Multi-label OR in WHERE (see patterns section)         |

---

## Reference

### pathfinding.cloud (Attack Path Definitions)

- **Repository**: https://github.com/DataDog/pathfinding.cloud
- **All paths JSON**: `https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json`
- Always use Bash with `curl | jq` to fetch paths (WebFetch truncates the large JSON)

### Cartography Schema

- **URL pattern**: `https://raw.githubusercontent.com/{org}/cartography/refs/tags/{version}/docs/root/modules/{provider}/schema.md`
- Always use the version from `api/pyproject.toml`, not master/main

### openCypher Specification

- **Neptune openCypher compliance** (what Neptune supports): https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html
- **openCypher project** (spec, grammar, TCK): https://github.com/opencypher/openCypher

---

## Learning from the Queries Module

**IMPORTANT**: Before creating a new query, ALWAYS read the entire queries module:

```
api/src/backend/api/attack_paths/queries/
├── __init__.py      # Module exports
├── types.py         # Type definitions
├── registry.py      # Registry logic
└── {provider}.py    # Provider queries (aws.py, etc.)
```

Use the existing queries to learn:

- Query structure and formatting
- Variable naming conventions
- How to include Prowler findings
- Comment style

**DO NOT** use generic templates. Match the exact style of existing queries in the file.
