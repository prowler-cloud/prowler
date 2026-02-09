---
name: prowler-attack-paths-query
description: >
  Creates Prowler Attack Paths openCypher queries for graph analysis (compatible with Neo4j and Neptune).
  Trigger: When creating or updating Attack Paths queries that detect privilege escalation paths,
  network exposure, or security misconfigurations in cloud environments.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
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

### Query Definition Pattern

```python
from api.attack_paths.queries.types import (
    AttackPathsQueryAttribution,
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL

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
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
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

**Additional Prowler Labels**: The Attack Paths sync task adds extra labels:

- `ProwlerFinding` - Prowler finding nodes with `status`, `provider_uid` properties
- `ProviderResource` - Generic resource marker
- `{Provider}Resource` - Provider-specific marker (e.g., `AWSResource`)

These are defined in `api/src/backend/tasks/jobs/attack_paths/config.py`.

### 3. Consult the Schema for Available Data

Use the Cartography schema to discover:

- What node labels exist for the target resources
- What properties are available on those nodes
- What relationships connect the nodes

This informs query design by showing what data is actually available to query.

### 4. Create Query Definition

Use the standard pattern (see above) with:

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
- `aws-rds-unencrypted-storage`

### Query Constant Name

```
{PROVIDER}_{CATEGORY}_{DESCRIPTION}
```

Examples:

- `AWS_EC2_PRIVESC_PASSROLE_IAM`
- `AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_ASSUME_ROLE`
- `AWS_RDS_UNENCRYPTED_STORAGE`

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

### Include Prowler Findings

```cypher
UNWIND nodes(path_principal) + nodes(path_target) as n
OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {status: 'FAIL', provider_uid: $provider_uid})

RETURN path_principal, path_target,
    collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
```

---

## Common Node Labels by Provider

### AWS

| Label                | Description                         |
| -------------------- | ----------------------------------- |
| `AWSAccount`         | AWS account root                    |
| `AWSPrincipal`       | IAM principal (user, role, service) |
| `AWSRole`            | IAM role                            |
| `AWSUser`            | IAM user                            |
| `AWSPolicy`          | IAM policy                          |
| `AWSPolicyStatement` | Policy statement                    |
| `EC2Instance`        | EC2 instance                        |
| `EC2SecurityGroup`   | Security group                      |
| `S3Bucket`           | S3 bucket                           |
| `RDSInstance`        | RDS database instance               |
| `LoadBalancer`       | Classic ELB                         |
| `LoadBalancerV2`     | ALB/NLB                             |
| `LaunchTemplate`     | EC2 launch template                 |

### Common Relationships

| Relationship           | Description             |
| ---------------------- | ----------------------- |
| `TRUSTS_AWS_PRINCIPAL` | Role trust relationship |
| `STS_ASSUMEROLE_ALLOW` | Can assume role         |
| `POLICY`               | Has policy attached     |
| `STATEMENT`            | Policy has statement    |

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

1. **Always filter by provider_uid**: Use `{id: $provider_uid}` on account nodes and `{provider_uid: $provider_uid}` on ProwlerFinding nodes

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

---

## openCypher Compatibility

Queries must be written in **openCypher Version 9** to ensure compatibility with both Neo4j and Amazon Neptune.

> **Why Version 9?** Amazon Neptune implements openCypher Version 9. By targeting this specification, queries work on both Neo4j and Neptune without modification.

### Avoid These (Not in openCypher spec)

| Feature                                             | Reason                                          |
| --------------------------------------------------- | ----------------------------------------------- |
| APOC procedures (`apoc.*`)                          | Neo4j-specific plugin, not available in Neptune |
| Virtual nodes (`apoc.create.vNode`)                 | APOC-specific                                   |
| Virtual relationships (`apoc.create.vRelationship`) | APOC-specific                                   |
| Neptune extensions                                  | Not available in Neo4j                          |
| `reduce()` function                                 | Use `UNWIND` + aggregation instead              |
| `FOREACH` clause                                    | Use `WITH` + `UNWIND` + `SET` instead           |
| Regex match operator (`=~`)                         | Not supported in Neptune                        |

### CALL Subqueries

Supported with limitations:

- Use `WITH` clause to import variables: `CALL { WITH var ... }`
- Updates inside CALL subqueries are NOT supported
- Emitted variables cannot overlap with variables before the CALL

---

## Reference

### pathfinding.cloud (Attack Path Definitions)

- **Repository**: https://github.com/DataDog/pathfinding.cloud
- **All paths JSON**: `https://raw.githubusercontent.com/DataDog/pathfinding.cloud/main/docs/paths.json`
- Use WebFetch to query specific paths or list available services

### Cartography Schema

- **URL pattern**: `https://raw.githubusercontent.com/{org}/cartography/refs/tags/{version}/docs/root/modules/{provider}/schema.md`
- Always use the version from `api/pyproject.toml`, not master/main

### openCypher Specification

- **Neptune openCypher compliance** (what Neptune supports): https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html
- **Rewriting Cypher for Neptune** (converting Neo4j-specific syntax): https://docs.aws.amazon.com/neptune/latest/userguide/migration-opencypher-rewrites.html
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

> **Compatibility Warning**: Some existing queries use Neo4j-specific features
> (e.g., `apoc.create.vNode`, `apoc.create.vRelationship`, regex `=~`) that are
> **NOT compatible** with Amazon Neptune. Use these queries to learn general
> patterns (structure, naming, Prowler findings integration, comment style) but
> **DO NOT copy APOC procedures or other Neo4j-specific syntax** into new queries.
> New queries must be pure openCypher Version 9. Refer to the
> [openCypher Compatibility](#opencypher-compatibility) section for the full list
> of features to avoid.

**DO NOT** use generic templates. Match the exact style of existing **compatible** queries in the file.
