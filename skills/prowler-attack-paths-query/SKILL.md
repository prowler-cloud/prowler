---
name: prowler-attack-paths-query
description: "Trigger: When creating or updating Prowler Attack Paths openCypher queries. Governs provider scoping, Cartography-schema grounding, Prowler-specific labels, and openCypher-safe query patterns."
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

## Activation Contract

Use this skill when editing predefined Attack Paths queries in `api/src/backend/api/attack_paths/queries/` or when designing query logic that must remain compatible with Neptune and Neo4j.

## Hard Rules

- Write openCypher Version 9 only; no APOC, Neptune-only extensions, fresh regex usage, `reduce()`, or `CALL ... UNION` shortcuts.
- For predefined queries, anchor on `MATCH (aws:AWSAccount {id: $provider_uid})...` and keep every additional `MATCH` chained from `aws` or a variable already proven to belong to that scoped subgraph.
- For custom-query behavior, do not add manual isolation boilerplate; the sanitizer injects provider labels automatically.
- Never use internal isolation labels in query text: `_ProviderResource`, `_AWSResource`, `_Tenant_*`, `_Provider_*`.
- Read the pinned Cartography dependency from `api/pyproject.toml` and ground every non-Prowler label, property, and relationship in that schema before writing Cypher.
- Use `PROWLER_FINDING_LABEL` via f-string interpolation; never hardcode `ProwlerFinding`.
- Deduplicate path nodes before the `OPTIONAL MATCH` that loads Prowler findings.
- Register every new predefined query in the provider query list.

## Decision Gates

| Question | Action |
|---|---|
| Is this a predefined repository query? | Manually anchor on `AWSAccount {id: $provider_uid}` and preserve path connectivity for every matched node. |
| Is this a custom query endpoint scenario? | Write plain Cypher and let the sanitizer inject provider isolation. |
| Is the attack path privilege escalation? | Pick the correct target pattern: self-escalation, lateral user, assumable role, or PassRole + service. |
| Is it a network exposure path? | Scope the resource first, then reach `(:Internet)-[:CAN_ACCESS]->(resource)` from that already-scoped node. |
| Need another permission check? | Add a second policy/statement match from the already-bound principal, not a new unscoped root match. |
| Unsure whether a label or property exists? | Stop guessing and verify against the pinned Cartography schema before proceeding. |

## Execution Steps

1. Read `types.py`, `registry.py`, and the provider query module to match existing constant names, registration style, and return shape.
2. Inspect `api/pyproject.toml` for the pinned Cartography source/version and verify every non-Prowler label, property, and relationship against that schema.
3. Choose the correct audience and pattern: predefined scoped query, custom sanitized query, privilege-escalation sub-pattern, or network-exposure pattern.
4. Build the query definition with stable naming: `{provider}-{category}-{description}` id, uppercase constant, plain-language descriptions, and attribution only when sourced.
5. Add inline comments, keep all matches scoped, use `PROWLER_FINDING_LABEL`, deduplicate nodes before `OPTIONAL MATCH`, and include `internet, can_access` only for network-exposure returns.
6. Add any parameter definitions with explicit typing when non-string input is required.
7. Register the constant in `{PROVIDER}_QUERIES` and re-check openCypher compatibility before finishing.

## Output Contract

- State whether the query is predefined or custom-query-oriented.
- Name the scoping anchor used and the attack pattern selected.
- Report which schema sources were verified locally (`api/pyproject.toml`, provider query module, pinned schema target/version).
- Mention whether the query includes Prowler finding enrichment, network exposure return values, or multi-permission logic.
- Confirm registration location and any parameters added.

## References

- `api/src/backend/api/attack_paths/queries/types.py`
- `api/src/backend/api/attack_paths/queries/registry.py`
- `api/src/backend/api/attack_paths/queries/{provider}.py`
- `api/src/backend/api/attack_paths/cypher_sanitizer.py`
- `api/src/backend/tasks/jobs/attack_paths/config.py`
- `api/pyproject.toml`
