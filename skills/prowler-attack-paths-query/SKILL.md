---
name: prowler-attack-paths-query
description: >
  Creates Prowler Attack Paths openCypher queries using the Cartography schema as the source of truth
  for node labels, properties, and relationships. Covers Prowler-specific additions (Internet node,
  ProwlerFinding, internal isolation labels), $provider_uid scoping, and list-property item nodes
  with typed `HAS_*` edges that run efficiently on both Neo4j and Amazon Neptune sinks.
  Trigger: When creating or updating Attack Paths queries.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "3.0"
  scope: [root, api]
  auto_invoke:
    - "Creating Attack Paths queries"
    - "Updating existing Attack Paths queries"
    - "Adding privilege escalation detection queries"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, Task
---

## Overview

Attack Paths queries are read-only openCypher queries over a Cartography-ingested cloud graph that detect privilege escalation chains, network exposure, and other graph-shaped security risks. Queries are written in openCypher Version 9 so they run on both Neo4j and Amazon Neptune sinks.

---

## Two query audiences

|                    | Predefined queries                                          | Custom queries                                                        |
| ------------------ | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| Where they live    | `api/src/backend/api/attack_paths/queries/{provider}.py`    | User-supplied via the custom query API endpoint                       |
| Provider isolation | `AWSAccount {id: $provider_uid}` anchor + path connectivity | Automatic `_Provider_{uuid}` label injection by `cypher_sanitizer.py` |
| What to write      | Chain every MATCH from the `aws` variable                   | Plain Cypher, no isolation boilerplate                                |
| Internal labels    | Never use                                                   | Never use (system-injected)                                           |

**Predefined queries**: every node must be reachable from the `AWSAccount` root via graph traversal. That is the isolation boundary.

**Custom queries**: write natural Cypher. The runner injects a `_Provider_{uuid}` label into every node pattern, and a post-query filter handles edge cases.

---

## Input sources

Two sources for new queries:

1. **pathfinding.cloud ID** (e.g. `ECS-001`, `GLUE-001`), the Datadog research catalogue. The aggregated `paths.json` is too large for WebFetch:

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

   If `jq` is unavailable, use `python3 -c "import json,sys; ..."`.

2. **Natural language description** from the requester.

---

## Query structure

### Provider scoping parameter

| Parameter       | Property | Used on      | Purpose                                |
| --------------- | -------- | ------------ | -------------------------------------- |
| `$provider_uid` | `id`     | `AWSAccount` | Scopes the query to a specific account |

The runner binds `$provider_uid` automatically. Every other node is isolated by path connectivity from the `AWSAccount` anchor.

### Imports

```python
from api.attack_paths.queries.types import (
    AttackPathsQueryAttribution,
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL
```

Always use `PROWLER_FINDING_LABEL` via f-string interpolation, never hardcode `"ProwlerFinding"`.

### Definition fields

- **id**: kebab-case `{provider}-{description}`, e.g. `aws-ec2-privesc-passrole-iam`.
- **name**: short, human-friendly label. Sourced queries append the reference ID: `"EC2 Instance Launch with Privileged Role (EC2-001)"`.
- **short_description**: one sentence, no technical permissions.
- **description**: full technical explanation, plain text.
- **provider**: `aws`, `azure`, `gcp`, `kubernetes`, or `github`.
- **cypher**: f-string Cypher body. Literal `{` / `}` are escaped as `{{` / `}}`.
- **parameters**: `parameters=[]` if none.
- **attribution**: optional `AttackPathsQueryAttribution(text, link)` for sourced queries. `link` uses the lowercase ID.

Append the constant to the `{PROVIDER}_QUERIES` list at the bottom of the provider file.

---

## Predefined query template

The canonical shape combines a principal walk, an optional target walk, deduplicated nodes, and a typed finding overlay:

```python
AWS_{QUERY_NAME} = AttackPathsQueryDefinition(
    id="aws-{kebab-case-name}",
    name="{Label} ({REFERENCE_ID})",
    short_description="{One sentence.}",
    description="{Full technical explanation.}",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - {REFERENCE_ID} - {permission}",
        link="https://pathfinding.cloud/paths/{reference_id_lowercase}",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with {permission}
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)-[:POLICY]->(policy:AWSPolicy)-[:STATEMENT]->(stmt:AWSPolicyStatement {{effect: 'Allow'}})
        MATCH (stmt)-[:HAS_ACTION]->(act:AWSPolicyStatementActionItem)
        WHERE toLower(act.value) IN ['{permission_lowercase}', '{service}:*']
           OR act.value = '*'

        // Target resources attached to the same principal (sub-patterns below)
        MATCH path_target = (aws)--(target_policy:AWSPolicy)--(principal)
        WHERE target_policy.arn CONTAINS $provider_uid
        MATCH (stmt)-[:HAS_RESOURCE]->(res:AWSPolicyStatementResourceItem)
        WHERE res.value = '*'
           OR target_policy.arn CONTAINS res.value

        WITH DISTINCT path_principal, path_target
        WITH collect(path_principal) + collect(path_target) AS paths
        UNWIND paths AS p
        UNWIND nodes(p) AS n

        WITH paths, collect(DISTINCT n) AS unique_nodes
        UNWIND unique_nodes AS n
        OPTIONAL MATCH (n)-[pfr:HAS_FINDING]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

        RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)
```

Key points:

- The principal walk types the `POLICY` and `STATEMENT` hops. Both are low-fan-out (each principal has a handful of policies; each policy a handful of statements), so the typed edge lets the planner cost a cheap inline filter.
- The `(aws)--` hub hops stay anonymous. `AWSAccount` is a high-degree node that fans out to every principal, role, policy, and resource in the account; typing those edges forces the planner to enumerate from the hub and collapses performance on multi-tenant Neptune.
- Other relationship types appear only where the file's existing queries already use one (`TRUSTS_AWS_PRINCIPAL`, `STS_ASSUMEROLE_ALLOW`, `MEMBER_AWS_GROUP`, `HAS_EXECUTION_ROLE`).
- The finding probe is typed `:HAS_FINDING` and left undirected. The type lets Neptune apply an inline edge filter; the lack of direction matches the convention of the rest of the file.
- Each `HAS_*` traversal is its own `MATCH` clause with a `WHERE` on the child item node. `WITH DISTINCT path_principal, path_target` precedes `collect(path...)` to dedupe the row multiplication produced by the joins.
- The `RETURN` shape `paths, dpf, dpfr` is the contract the serializer and visualiser depend on. Do not change it.

---

## Privilege escalation sub-patterns

Four `path_target` shapes cover the common attack types. Each shares the canonical template's `path_principal`, deduplication tail, and `RETURN`; only the `path_target` MATCH and its resource predicate differ.

| Sub-pattern         | Target                   | `path_target` shape                                                                                     | Example |
| ------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------- | ------- |
| Self-escalation     | Principal's own policies | `(aws)--(target_policy:AWSPolicy)--(principal)`                                                         | IAM-001 |
| Lateral to user     | Other IAM users          | `(aws)--(target_user:AWSUser)`                                                                          | IAM-002 |
| Assume-role lateral | Assumable roles          | `(aws)--(target_role:AWSRole)-[:STS_ASSUMEROLE_ALLOW]-(principal)`                                      | IAM-014 |
| PassRole + service  | Service-trusting roles   | `(aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]-(:AWSPrincipal {arn: '{service}.amazonaws.com'})` | EC2-001 |

**Multi-permission queries** (e.g. PassRole plus a service-create action) add a second walk before `path_target`. Reuse the per-query counter for the new variables (`act2`, `policy2`, `stmt2`):

```cypher
MATCH (principal)-[:POLICY]->(policy2:AWSPolicy)-[:STATEMENT]->(stmt2:AWSPolicyStatement {effect: 'Allow'})
MATCH (stmt2)-[:HAS_ACTION]->(act2:AWSPolicyStatementActionItem)
WHERE toLower(act2.value) IN ['service:*', 'service:createsomething']
   OR act2.value = '*'
```

Both `stmt.resource` and `stmt2.resource` are then checked against the target via two `HAS_RESOURCE` traversals (`res`, `res2`). See IAM-015 or EC2-001 in `aws.py`.

---

## Network exposure pattern

The Internet node is reached via `CAN_ACCESS` through an already-scoped resource, never as a standalone lookup:

```python
cypher=f"""
    // Resource scoped through the account anchor
    MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(resource:EC2Instance)
    WHERE resource.exposed_internet = true

    // Internet node reached via path connectivity through the resource
    OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(resource)

    WITH collect(path) AS paths, head(collect(internet)) AS internet, collect(can_access) AS can_access
    UNWIND paths AS p
    UNWIND nodes(p) AS n

    WITH paths, internet, can_access, collect(DISTINCT n) AS unique_nodes
    UNWIND unique_nodes AS n
    OPTIONAL MATCH (n)-[pfr:HAS_FINDING]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

    RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
        internet, can_access
"""
```

The `CAN_ACCESS` edge stays typed and directed (`-[:CAN_ACCESS]->`); that is its canonical sync-time orientation.

---

## List-typed properties as child nodes

Some Cartography node properties carry a list of values: `AWSPolicyStatement.action`, `AWSPolicyStatement.resource`, `KMSKey.encryption_algorithms`, `CloudFrontDistribution.aliases`, and many others. The graph models each such property as a set of child item nodes connected to the parent by a typed edge. Queries reach the values by traversing the edge; the parent does not carry the list as a single field.

### Naming convention

For a list-typed parent property the sink stores:

- **Child label**: `<ParentLabel><PropertyPascal>Item`. Example: `AWSPolicyStatement.resource` → `AWSPolicyStatementResourceItem`.
- **Edge type**: `HAS_<PROPERTY_UPPER>`. Example: `resource` → `HAS_RESOURCE`.
- **Child property**: `value` (a single scalar string) for scalar-list properties. For list-of-dict properties (rare; for example `SecretsManagerSecretVersion.tags`) the child carries the dict keys as named fields per the catalog's `field_map`.

### Variable naming for child-item matches

`aws.py` uses a per-query counter for each `HAS_*` traversal so chained matches stay unambiguous:

| Edge              | First | Second | Third |
| ----------------- | ----- | ------ | ----- |
| `HAS_ACTION`      | `act` | `act2` | `act3` |
| `HAS_RESOURCE`    | `res` | `res2` | `res3` |
| `HAS_NOTACTION`   | `nact` | `nact2` | `nact3` |
| `HAS_NOTRESOURCE` | `nres` | `nres2` | `nres3` |

The counter resets at the top of every query.

### Example - action match

Find statements that grant `iam:PassRole`, `iam:*`, or `*`. Traverse the `HAS_ACTION` edge in its own `MATCH` clause and apply the predicate in the attached `WHERE`:

```cypher
MATCH (stmt:AWSPolicyStatement {effect: 'Allow'})
MATCH (stmt)-[:HAS_ACTION]->(act:AWSPolicyStatementActionItem)
WHERE toLower(act.value) IN ['iam:passrole', 'iam:*']
   OR act.value = '*'
```

The literal-action list is case-folded with `toLower(act.value)` because IAM authors mix case (`iam:PassRole`, `iam:passrole`); the `*` wildcard never lower-cases.

### Example - resource ARN match

Find statements whose resource can target a specific role:

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)
MATCH (stmt)-[:HAS_RESOURCE]->(res:AWSPolicyStatementResourceItem)
WHERE res.value = '*'
   OR res.value CONTAINS target_role.name
   OR target_role.arn CONTAINS res.value
```

Three predicates cover the cases: full wildcard (`*`), pattern containing the role name (`arn:aws:iam::*:role/admin*`), and pattern that is a prefix or component of the actual ARN.

### Catalog of list properties

The provider catalog lives in `api/src/backend/tasks/jobs/attack_paths/provider_config.py` (`AWS_NORMALIZED_LISTS`). Beyond policy statements it includes KMS algorithms, ECS container-definition lists (`entry_point`, `command`, `links`, `dns_servers`, ...), CloudFront aliases, Inspector finding URL and vulnerability lists, RDS event-subscription categories, and others. To query a list property that is not in the catalog, add an entry there first so the sync layer materialises it.

---

## Common openCypher patterns

### Match account and principal

```cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)-[:POLICY]->(policy:AWSPolicy)-[:STATEMENT]->(stmt:AWSPolicyStatement {effect: 'Allow'})
```

The `(aws)--(principal)` hop stays anonymous; the `POLICY` and `STATEMENT` hops are typed.

### Roles trusting a service

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]-(:AWSPrincipal {arn: 'ec2.amazonaws.com'})
```

### Roles a principal can assume

```cypher
MATCH path_target = (aws)--(target_role:AWSRole)-[:STS_ASSUMEROLE_ALLOW]-(principal)
```

### JSON-encoded properties

Object-typed Cartography properties (most notably `condition` on `AWSPolicyStatement` and `S3PolicyStatement`) are stored as JSON-encoded strings, e.g. `'{"StringEquals":{"aws:SourceAccount":"123456789012"}}'`. There is no JSON parser at query time, so use `CONTAINS` for substring checks:

```cypher
WHERE stmt.condition CONTAINS '"aws:SourceAccount"'
```

For structured inspection, fetch the rows and parse in Python. Cypher cannot navigate JSON object keys.

### Internet node via path connectivity

```cypher
OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(resource)
```

`resource` must already be bound by the account-anchored pattern above.

### Multi-label OR (multiple resource types)

```cypher
MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x)-[q]-(y)
WHERE (x:EC2PrivateIp AND x.public_ip = $ip)
   OR (x:EC2Instance AND x.publicipaddress = $ip)
   OR (x:NetworkInterface AND x.public_ip = $ip)
   OR (x:ElasticIPAddress AND x.public_ip = $ip)
```

### Include Prowler findings

Deduplicate nodes before the typed finding probe to avoid one `OPTIONAL MATCH` per path-occurrence of the same node:

```cypher
WITH collect(path_principal) + collect(path_target) AS paths
UNWIND paths AS p
UNWIND nodes(p) AS n

WITH paths, collect(DISTINCT n) AS unique_nodes
UNWIND unique_nodes AS n
OPTIONAL MATCH (n)-[pfr:HAS_FINDING]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
```

For network-exposure queries, aggregate the Internet node and its edge alongside paths:

```cypher
WITH collect(path) AS paths, head(collect(internet)) AS internet, collect(can_access) AS can_access
UNWIND paths AS p
UNWIND nodes(p) AS n

WITH paths, internet, can_access, collect(DISTINCT n) AS unique_nodes
UNWIND unique_nodes AS n
OPTIONAL MATCH (n)-[pfr:HAS_FINDING]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})

RETURN paths, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
    internet, can_access
```

---

## Prowler-specific labels and relationships

Added by the sync task, not part of the Cartography schema. For everything else, consult the pinned Cartography schema (see "Creation steps").

| Label / Relationship   | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `ProwlerFinding`       | Finding node (`status`, `severity`, `check_id`)             |
| `Internet`             | Internet sentinel node                                      |
| `CAN_ACCESS`           | `(Internet)-[:CAN_ACCESS]->(resource)` exposure edge        |
| `HAS_FINDING`          | `(resource)-[:HAS_FINDING]->(:ProwlerFinding)` finding link |
| `TRUSTS_AWS_PRINCIPAL` | Role trust relationship                                     |
| `STS_ASSUMEROLE_ALLOW` | Can assume role                                             |

---

## Parameters

For queries that take user input:

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

## openCypher compatibility

Queries must run on both Neo4j and Amazon Neptune. Avoid these constructs:

| Feature                    | Use instead                                              |
| -------------------------- | -------------------------------------------------------- |
| APOC procedures (`apoc.*`) | Real nodes and relationships in the graph                |
| Neptune extensions         | Standard openCypher                                      |
| `reduce()`                 | `UNWIND` + `collect()`                                   |
| `FOREACH`                  | `WITH` + `UNWIND` + `SET`                                |
| Regex `=~`                 | `toLower()` + exact match, or `STARTS WITH` / `CONTAINS` |
| `CALL () { UNION }`        | Multi-label `OR` in `WHERE` (see pattern above)          |
| `any(x IN list ...)`       | `size([x IN list WHERE pred]) > 0`                       |
| `all(x IN list ...)`       | `size([x IN list WHERE pred]) = size(list)`              |
| `none(x IN list ...)`      | `size([x IN list WHERE pred]) = 0`                       |
| `EXISTS { MATCH (pattern) WHERE pred }` | Standalone `MATCH (pattern)` + `WHERE pred`; precede the downstream `collect(path...)` with `WITH DISTINCT <path-vars>` to dedupe the joins |

For list-typed properties in the catalog (action, resource, and so on), traverse the `HAS_*` edges to the child item nodes via the multi-`MATCH` shape shown in "List-typed properties as child nodes". The parent node does not carry the list as a single field, so `split(...)` and comma-string predicates do not apply.

---

## Best practices

1. **Chain every MATCH from the account anchor.** An unanchored `MATCH (role:AWSRole)` returns roles from every provider in the graph; `MATCH (aws)--(role:AWSRole)` is scoped. A second-permission MATCH like `MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)` is safe because `principal` is already bound to the account's subgraph.
2. **Type the finding probe.** Always `OPTIONAL MATCH (n)-[pfr:HAS_FINDING]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL'}})`. The type lets Neptune apply an inline edge filter; an untyped probe scans every incident edge of high-degree nodes.
3. **Comment each MATCH.** One inline `// ...` line per clause explaining its role.
4. **Never use internal labels.** `_ProviderResource`, `_AWSResource`, `_Tenant_*`, `_Provider_*` are system isolation labels and must not appear in query text (predefined or custom).
5. **Reach the Internet node through path connectivity** via `(internet:Internet)-[:CAN_ACCESS]->(resource)`, never as a standalone match.
6. **Preserve the `RETURN` contract.** `paths, dpf, dpfr` for the standard shape; add `internet, can_access` for network-exposure queries. The serializer and visualiser depend on these names.

---

## Naming conventions

- **ID**: kebab-case `{provider}-{category}-{description}`, e.g. `aws-ec2-privesc-passrole-iam`.
- **Constant**: SHOUTING*SNAKE_CASE `{PROVIDER}*{CATEGORY}\_{DESCRIPTION}`, e.g. `AWS_EC2_PRIVESC_PASSROLE_IAM`.

---

## Creation steps

1. **Read the queries module first** to match the existing style:

   ```
   api/src/backend/api/attack_paths/queries/
   ├── __init__.py
   ├── types.py         # dataclass definitions
   ├── registry.py
   └── {provider}.py
   ```

2. **Fetch the Cartography schema for the pinned version.** Do not guess labels, properties, or relationships. Read the dependency pin:

   ```bash
   grep cartography api/pyproject.toml
   ```

   Then fetch the schema for that exact tag:

   ```
   # Git pin (prowler-cloud/cartography@<TAG>):
   https://raw.githubusercontent.com/prowler-cloud/cartography/refs/tags/<TAG>/docs/root/modules/{provider}/schema.md

   # PyPI pin (cartography==<TAG>):
   https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/<TAG>/docs/root/modules/{provider}/schema.md
   ```

3. **Build the query** using the canonical predefined template plus the appropriate sub-pattern (privilege escalation or network exposure). For list-typed properties (action/resource/etc.), traverse the exploded child nodes via `[:HAS_ACTION]->(:AWSPolicyStatementActionItem)` etc. (see "List-typed properties as child nodes" and the `AWS_NORMALIZED_LISTS` catalog).

4. **Register** the constant in the `{PROVIDER}_QUERIES` list at the bottom of the provider file.

---

## Reference

- **pathfinding.cloud**: https://github.com/DataDog/pathfinding.cloud (use `curl | jq`; the aggregated `paths.json` is too large for WebFetch).
- **Cartography schema** (per pinned tag): `https://raw.githubusercontent.com/{org}/cartography/refs/tags/{tag}/docs/root/modules/{provider}/schema.md`.
- **Neptune openCypher compliance**: https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html.
- **openCypher spec**: https://github.com/opencypher/openCypher.
- **Sync converter** (`tasks/jobs/attack_paths/sync.py`): list-typed node properties listed in `tasks/jobs/attack_paths/provider_config.py::AWS_NORMALIZED_LISTS` are materialised as child item nodes + `HAS_*` edges. Properties that are not in the catalog are serialised to a comma-delimited string and emit a one-time warning. Dict-typed properties become JSON strings. Same shape on both sinks.
