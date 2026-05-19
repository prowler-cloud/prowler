---
name: prowler-attack-paths-query
description: >
  Creates Prowler Attack Paths openCypher queries using the Cartography schema as the source of truth
  for node labels, properties, and relationships. Covers Prowler-specific additions (Internet node,
  ProwlerFinding, internal isolation labels), $provider_uid scoping, and the comma-string predicate
  shapes that run efficiently on both Neo4j and Amazon Neptune sinks.
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

| | Predefined queries | Custom queries |
|---|---|---|
| Where they live | `api/src/backend/api/attack_paths/queries/{provider}.py` | User-supplied via the custom query API endpoint |
| Provider isolation | `AWSAccount {id: $provider_uid}` anchor + path connectivity | Automatic `_Provider_{uuid}` label injection by `cypher_sanitizer.py` |
| What to write | Chain every MATCH from the `aws` variable | Plain Cypher, no isolation boilerplate |
| Internal labels | Never use | Never use (system-injected) |

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

| Parameter | Property | Used on | Purpose |
|---|---|---|---|
| `$provider_uid` | `id` | `AWSAccount` | Scopes the query to a specific account |

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
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement {{effect: 'Allow'}})
        WHERE (
            toLower(stmt.action) = '{permission_lowercase}'
            OR toLower(stmt.action) STARTS WITH '{permission_lowercase},'
            OR toLower(stmt.action) ENDS WITH ',{permission_lowercase}'
            OR toLower(stmt.action) CONTAINS ',{permission_lowercase},'
            OR toLower(stmt.action) = '{service}:*'
            OR toLower(stmt.action) STARTS WITH '{service}:*,'
            OR toLower(stmt.action) ENDS WITH ',{service}:*'
            OR toLower(stmt.action) CONTAINS ',{service}:*,'
            OR stmt.action = '*'
            OR stmt.action STARTS WITH '*,'
            OR stmt.action ENDS WITH ',*'
            OR stmt.action CONTAINS ',*,'
        )

        // Target resources attached to the same principal (sub-patterns below)
        MATCH path_target = (aws)--(target_policy:AWSPolicy)--(principal)
        WHERE target_policy.arn CONTAINS $provider_uid
            AND (
                stmt.resource = '*'
                OR stmt.resource STARTS WITH '*,'
                OR stmt.resource ENDS WITH ',*'
                OR stmt.resource CONTAINS ',*,'
                OR size([resource IN split(stmt.resource, ",") WHERE target_policy.arn CONTAINS resource]) > 0
            )

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

- Cartography hops use anonymous `--`. Add a relationship type only where the file's existing queries already use one (`TRUSTS_AWS_PRINCIPAL`, `STS_ASSUMEROLE_ALLOW`, `MEMBER_AWS_GROUP`, `HAS_EXECUTION_ROLE`).
- The finding probe is typed `:HAS_FINDING` and left undirected. The type lets Neptune apply an inline edge filter; the lack of direction matches the convention of the rest of the file.
- The `WHERE` uses comma-string predicates (see "Comma-string predicate shapes"). `split()` appears only in the resource clause as the unavoidable token-as-needle fallback.
- The `RETURN` shape `paths, dpf, dpfr` is the contract the serializer and visualiser depend on. Do not change it.

---

## Privilege escalation sub-patterns

Four `path_target` shapes cover the common attack types. Each shares the canonical template's `path_principal`, deduplication tail, and `RETURN`; only the `path_target` MATCH and its resource predicate differ.

| Sub-pattern | Target | `path_target` shape | Example |
|---|---|---|---|
| Self-escalation | Principal's own policies | `(aws)--(target_policy:AWSPolicy)--(principal)` | IAM-001 |
| Lateral to user | Other IAM users | `(aws)--(target_user:AWSUser)` | IAM-002 |
| Assume-role lateral | Assumable roles | `(aws)--(target_role:AWSRole)-[:STS_ASSUMEROLE_ALLOW]-(principal)` | IAM-014 |
| PassRole + service | Service-trusting roles | `(aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]-(:AWSPrincipal {arn: '{service}.amazonaws.com'})` | EC2-001 |

**Multi-permission queries** (e.g. PassRole plus a service-create action) add a second walk before `path_target`:

```cypher
MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement {effect: 'Allow'})
WHERE <comma-string predicates over stmt2.action>
```

Both `stmt.resource` and `stmt2.resource` are then checked against the target via the same wrapper. See IAM-015 or EC2-001 in `aws.py`.

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

## Comma-string predicate shapes

`AWSPolicyStatement.action`, `resource`, `notaction`, and `notresource` are stored as comma-joined strings on both sinks. The sync converter (`tasks/jobs/attack_paths/sync.py`) normalises lists this way so queries are portable across backends.

The naive read is `size([x IN split(prop, ',') WHERE pred]) > 0`. On Neptune that operator falls off the DFE fast path and resolves every produced token through the term dictionary, per row, giving a 60-second tail on even a few hundred statements. String predicates over the raw stored value (`=`, `STARTS WITH`, `ENDS WITH`, `CONTAINS`) avoid list materialisation entirely and stay fast on both sinks.

For each predicate intent, prefer the corresponding string-op rewrite. Let `P` be the stored property and `L` the literal needle.

| Intent (per token semantics) | Use this on `P` (no `split`) |
|---|---|
| Token equals `L` | `P = 'L' OR P STARTS WITH 'L,' OR P ENDS WITH ',L' OR P CONTAINS ',L,'` |
| Case-insensitive equality | Wrap `P` in `toLower(P)` on all four clauses; lowercase `L` |
| Token starts with `'pre'` | `toLower(P) STARTS WITH 'pre' OR toLower(P) CONTAINS ',pre'` |
| Token contains `'sub'` | `toLower(P) CONTAINS 'sub'` |
| Token contains a dynamic value | `P CONTAINS <expr>` |
| At least one disjunct holds | `( … OR … )` over the above |
| No token matches | `NOT ( … OR … )` |

Two intents do not have a clean `split`-free rewrite:

- **Every token must match** (`size([x IN split WHERE P]) = size(split)`). No string-op equivalent; keep the `split` form when truly needed.
- **Token-as-needle**, where the loop variable is the needle inside a dynamic haystack such as `<dyn>.arn CONTAINS x`. See the wrapper below.

### Worked example

For `size([x IN split(stmt.action, ',') WHERE x = '*']) > 0`:

```cypher
WHERE (
    stmt.action = '*'
    OR stmt.action STARTS WITH '*,'
    OR stmt.action ENDS WITH ',*'
    OR stmt.action CONTAINS ',*,'
)
```

For an IAM PassRole check combining a specific action, the service wildcard, and `*`, expand each token via the four-clause membership and join with `OR`. The block ends up around twelve `OR`s; wrap in `( … )` so it composes cleanly with adjacent `AND` clauses.

---

## When `split` is unavoidable: the short-circuit wrapper

The token-as-needle shape, "does any token of the policy resource appear inside the target ARN", has no equivalent string-op rewrite. Substring containment in either direction is unsafe:

- `<dyn>.arn CONTAINS P` produces false negatives for multi-token resource lists (commas never appear in ARNs).
- `P CONTAINS <dyn>.arn` produces false positives whenever role names share a prefix (`app` vs `app-admin`).

The correct shape is a short-circuit wrapper that puts the cheap clauses first and isolates the `split` to the last `OR` operand:

```cypher
WHERE (
    P = '*'
    OR P STARTS WITH '*,'
    OR P ENDS WITH ',*'
    OR P CONTAINS ',*,'
    OR P CONTAINS <dyn>.name
    OR size([resource IN split(P, ",") WHERE <dyn>.arn CONTAINS resource]) > 0
)
```

`P` is the stored property (e.g. `stmt_passrole.resource`); `<dyn>` is the target node bound earlier (`target_role`, `target_user`, etc.). When any cheap clause holds (the common `*` and exact-name cases), the `size(split)` operand is never evaluated. The fallback runs only on specific-ARN-list policies that did not match the cheap clauses, and even then on a small set anchored by the preceding `TRUSTS_AWS_PRINCIPAL` or `STS_ASSUMEROLE_ALLOW` walk.

The two-disjunct variant (e.g. `target_policy`, which has no name attribute the policy resource would match) drops the `P CONTAINS <dyn>.name` line.

---

## Common openCypher patterns

### Match account and principal

```cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement {effect: 'Allow'})
```

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

| Label / Relationship | Description |
|---|---|
| `ProwlerFinding` | Finding node (`status`, `severity`, `check_id`) |
| `Internet` | Internet sentinel node |
| `CAN_ACCESS` | `(Internet)-[:CAN_ACCESS]->(resource)` exposure edge |
| `HAS_FINDING` | `(resource)-[:HAS_FINDING]->(:ProwlerFinding)` finding link |
| `TRUSTS_AWS_PRINCIPAL` | Role trust relationship |
| `STS_ASSUMEROLE_ALLOW` | Can assume role |

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

| Feature | Use instead |
|---|---|
| APOC procedures (`apoc.*`) | Real nodes and relationships in the graph |
| Neptune extensions | Standard openCypher |
| `reduce()` | `UNWIND` + `collect()` |
| `FOREACH` | `WITH` + `UNWIND` + `SET` |
| Regex `=~` | `toLower()` + exact match, or `STARTS WITH` / `CONTAINS` |
| `CALL () { UNION }` | Multi-label `OR` in `WHERE` (see pattern above) |
| `any(x IN list ...)` | `size([x IN list WHERE pred]) > 0` |
| `all(x IN list ...)` | `size([x IN list WHERE pred]) = size(list)` |
| `none(x IN list ...)` | `size([x IN list WHERE pred]) = 0` |

For comma-string properties, prefer the rewrites in "Comma-string predicate shapes" over the `size([x IN split ...])` form.

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
- **Constant**: SHOUTING_SNAKE_CASE `{PROVIDER}_{CATEGORY}_{DESCRIPTION}`, e.g. `AWS_EC2_PRIVESC_PASSROLE_IAM`.

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

3. **Build the query** using the canonical predefined template plus the appropriate sub-pattern (privilege escalation or network exposure). Apply the comma-string predicate shapes for `action` and `resource`; apply the short-circuit wrapper only where the token-as-needle case demands it.

4. **Register** the constant in the `{PROVIDER}_QUERIES` list at the bottom of the provider file.

---

## Reference

- **pathfinding.cloud**: https://github.com/DataDog/pathfinding.cloud (use `curl | jq`; the aggregated `paths.json` is too large for WebFetch).
- **Cartography schema** (per pinned tag): `https://raw.githubusercontent.com/{org}/cartography/refs/tags/{tag}/docs/root/modules/{provider}/schema.md`.
- **Neptune openCypher compliance**: https://docs.aws.amazon.com/neptune/latest/userguide/feature-opencypher-compliance.html.
- **openCypher spec**: https://github.com/opencypher/openCypher.
- **Sync converter** (`tasks/jobs/attack_paths/sync.py`): list values become comma-strings, dicts become JSON strings, applied uniformly to both sinks.
