import type { SkillDefinition } from "../types";

export const customAttackPathQuerySkill: SkillDefinition = {
  metadata: {
    id: "attack-path-custom-query",
    name: "Attack Paths Custom Query",
    description:
      "Write an openCypher graph query against Cartography-ingested cloud infrastructure to analyze attack paths, privilege escalation, and network exposure.",
  },
  instructions: `# Attack Paths Custom Query Skill

This skill provides openCypher syntax guidance and Cartography schema knowledge for writing graph queries against Prowler's cloud infrastructure data.

## Workflow

Follow these steps when the user asks you to write a custom openCypher query:

1. **Find a completed scan**: Use \`prowler_app_list_attack_paths_scans\` (filter by \`state=['completed']\`) to find a scan for the user's provider. You need the \`scan_id\` for the next step.

2. **Fetch the Cartography schema**: Use \`prowler_app_get_attack_paths_cartography_schema\` with the \`scan_id\`. This returns the full schema markdown with all node labels, relationships, and properties for the scan's provider and Cartography version. If this tool fails, use the Cartography Schema Reference section below as a fallback (AWS only).

3. **Analyze the schema**: From \`schema_content\`, identify the node labels, properties, and relationships relevant to the user's request. Cross-reference with the Common openCypher Patterns section below.

4. **Write the query**: Compose the openCypher query following all rules in this skill:
   - Scope every MATCH to the root account node (see Provider Isolation)
   - Use \`$provider_uid\` and \`$provider_id\` parameters (see Query Parameters)
   - Include \`ProwlerFinding\` OPTIONAL MATCH (see Include Prowler Findings)
   - Use openCypher v9 compatible syntax only (see openCypher Version 9 Compatibility)

5. **Present the query**: Show the complete query in a \`cypher\` code block with:
   - A brief explanation of what the query finds
   - The node types and relationships it traverses
   - What results to expect

**Note**: Custom queries cannot be executed through the available tools yet. Present the query to the user for review and manual execution.

## Query Parameters

All queries receive these built-in parameters (do NOT hardcode these values):

| Parameter | Matches property | Used on | Purpose |
|-----------|-----------------|---------|---------|
| \`$provider_uid\` | \`id\` | \`AWSAccount\` | Scopes to a specific cloud account |
| \`$provider_id\` | \`_provider_id\` | Any non-account node | Scopes nodes to the provider context |

Use \`$provider_uid\` on account root nodes. Use \`$provider_id\` on other nodes that need provider scoping (e.g., \`Internet\`).

## openCypher Query Guidelines

### Provider Isolation (CRITICAL)

Every query MUST chain from the root account node to prevent cross-provider data leakage.
The tenant database contains data from multiple providers.

\`\`\`cypher
// CORRECT: scoped to the specific account's subgraph
MATCH (aws:AWSAccount {id: $provider_uid})--(role:AWSRole)
WHERE role.name = 'admin'

// WRONG: matches ALL AWSRoles across all providers
MATCH (role:AWSRole) WHERE role.name = 'admin'
\`\`\`

Every \`MATCH\` clause must connect to the \`aws\` variable (or another variable already bound to the account's subgraph). An unanchored \`MATCH\` returns nodes from all providers.

**Exception**: The \`Internet\` sentinel node uses \`OPTIONAL MATCH\` with \`_provider_id\` for scoping instead of chaining from \`aws\`.

### Include Prowler Findings

Always include Prowler findings to enrich results with security context:

\`\`\`cypher
UNWIND nodes(path) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
\`\`\`

For network exposure queries, also return the internet node and relationship:

\`\`\`cypher
RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
    internet, can_access
\`\`\`

### openCypher Version 9 Compatibility

Queries must use openCypher Version 9 (compatible with both Neo4j and Amazon Neptune).

| Avoid | Reason | Use instead |
|-------|--------|-------------|
| APOC procedures (\`apoc.*\`) | Neo4j-specific plugin | Real nodes and relationships in the graph |
| Neptune extensions | Not available in Neo4j | Standard openCypher |
| \`reduce()\` function | Not in openCypher spec | \`UNWIND\` + \`collect()\` |
| \`FOREACH\` clause | Not in openCypher spec | \`WITH\` + \`UNWIND\` + \`SET\` |
| Regex operator (\`=~\`) | Not supported in Neptune | \`toLower()\` + exact match, or \`CONTAINS\`/\`STARTS WITH\` |
| \`CALL () { UNION }\` | Complex, hard to maintain | Multi-label OR in WHERE (see patterns below) |

**Supported with limitations:**
- \`CALL\` subqueries require \`WITH\` clause to import variables

## Cartography Schema Reference (Quick Reference / Fallback)

### AWS Node Labels

| Label | Description |
|-------|-------------|
| \`AWSAccount\` | AWS account root node |
| \`AWSPrincipal\` | IAM principal (user, role, service) |
| \`AWSRole\` | IAM role |
| \`AWSUser\` | IAM user |
| \`AWSPolicy\` | IAM policy |
| \`AWSPolicyStatement\` | Policy statement with effect, action, resource |
| \`EC2Instance\` | EC2 instance |
| \`EC2SecurityGroup\` | Security group |
| \`EC2PrivateIp\` | EC2 private IP (has \`public_ip\`) |
| \`IpPermissionInbound\` | Inbound security group rule |
| \`IpRange\` | IP range (e.g., \`0.0.0.0/0\`) |
| \`NetworkInterface\` | ENI (has \`public_ip\`) |
| \`ElasticIPAddress\` | Elastic IP (has \`public_ip\`) |
| \`S3Bucket\` | S3 bucket |
| \`RDSInstance\` | RDS database instance |
| \`LoadBalancer\` | Classic ELB |
| \`LoadBalancerV2\` | ALB/NLB |
| \`ELBListener\` | Classic ELB listener |
| \`ELBV2Listener\` | ALB/NLB listener |
| \`LaunchTemplate\` | EC2 launch template |
| \`AWSTag\` | Resource tag with key/value properties |

### Prowler-Specific Labels

| Label | Description |
|-------|-------------|
| \`ProwlerFinding\` | Prowler finding node with \`status\`, \`provider_uid\`, \`severity\` properties |
| \`Internet\` | Internet sentinel node, scoped by \`_provider_id\` (used in network exposure queries) |

### Common Relationships

| Relationship | Description |
|-------------|-------------|
| \`TRUSTS_AWS_PRINCIPAL\` | Role trust relationship |
| \`STS_ASSUMEROLE_ALLOW\` | Can assume role (variable-length for chains) |
| \`CAN_ACCESS\` | Internet-to-resource exposure link |
| \`POLICY\` | Has policy attached |
| \`STATEMENT\` | Policy has statement |

### Key Properties

- \`AWSAccount\`: \`id\` (account ID used with \`$provider_uid\`)
- \`AWSPolicyStatement\`: \`effect\` ('Allow'/'Deny'), \`action\` (list), \`resource\` (list)
- \`EC2Instance\`: \`exposed_internet\` (boolean), \`publicipaddress\`
- \`EC2PrivateIp\`: \`public_ip\`
- \`NetworkInterface\`: \`public_ip\`
- \`ElasticIPAddress\`: \`public_ip\`
- \`EC2SecurityGroup\`: \`name\`, \`id\`
- \`IpPermissionInbound\`: \`toport\`, \`fromport\`, \`protocol\`
- \`S3Bucket\`: \`name\`, \`anonymous_access\` (boolean)
- \`RDSInstance\`: \`storage_encrypted\` (boolean)
- \`ProwlerFinding\`: \`status\` ('FAIL'/'PASS'/'MANUAL'), \`severity\`, \`provider_uid\`
- \`Internet\`: \`_provider_id\` (provider UUID used with \`$provider_id\`)

## Common openCypher Patterns

### Match Account and Principal

\`\`\`cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
\`\`\`

### Check IAM Action Permissions

\`\`\`cypher
WHERE stmt.effect = 'Allow'
    AND any(action IN stmt.action WHERE
        toLower(action) = 'iam:passrole'
        OR toLower(action) = 'iam:*'
        OR action = '*'
    )
\`\`\`

### Find Roles Trusting a Service

\`\`\`cypher
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: 'ec2.amazonaws.com'})
\`\`\`

### Check Resource Scope

\`\`\`cypher
WHERE any(resource IN stmt.resource WHERE
    resource = '*'
    OR target_role.arn CONTAINS resource
    OR resource CONTAINS target_role.name
)
\`\`\`

### Match Internet Sentinel Node

Used in network exposure queries. The Internet node is a real graph node, scoped by \`_provider_id\`:

\`\`\`cypher
OPTIONAL MATCH (internet:Internet {_provider_id: $provider_id})
\`\`\`

### Link Internet to Exposed Resource

The \`CAN_ACCESS\` relationship links the Internet node to exposed resources:

\`\`\`cypher
OPTIONAL MATCH (internet)-[can_access:CAN_ACCESS]->(resource)
\`\`\`

### Multi-label OR (match multiple resource types)

When a query needs to match different resource types in the same position, use label checks in WHERE:

\`\`\`cypher
MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x)-[q]-(y)
WHERE (x:EC2PrivateIp AND x.public_ip = $ip)
   OR (x:EC2Instance AND x.publicipaddress = $ip)
   OR (x:NetworkInterface AND x.public_ip = $ip)
   OR (x:ElasticIPAddress AND x.public_ip = $ip)
\`\`\`

## Example Query Patterns

### Resource Inventory

\`\`\`cypher
MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)

UNWIND nodes(path) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
\`\`\`

### Network Exposure

\`\`\`cypher
// Match the Internet sentinel node
OPTIONAL MATCH (internet:Internet {_provider_id: $provider_id})

// Match exposed resources (MUST chain from aws)
MATCH path = (aws:AWSAccount {id: $provider_uid})--(resource:EC2Instance)
WHERE resource.exposed_internet = true

// Link Internet to resource
OPTIONAL MATCH (internet)-[can_access:CAN_ACCESS]->(resource)

UNWIND nodes(path) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr,
    internet, can_access
\`\`\`

### IAM Permission Check

\`\`\`cypher
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
WHERE stmt.effect = 'Allow'
    AND any(action IN stmt.action WHERE
        toLower(action) = 'iam:passrole'
        OR toLower(action) = 'iam:*'
        OR action = '*'
    )

UNWIND nodes(path_principal) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path_principal, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
\`\`\`

### Privilege Escalation (Role Assumption Chain)

\`\`\`cypher
// Find principals with iam:PassRole
MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
WHERE stmt.effect = 'Allow'
    AND any(action IN stmt.action WHERE
        toLower(action) = 'iam:passrole'
        OR toLower(action) = 'iam:*'
        OR action = '*'
    )

// Find target roles trusting a service
MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: 'ec2.amazonaws.com'})
WHERE any(resource IN stmt.resource WHERE
    resource = '*'
    OR target_role.arn CONTAINS resource
    OR resource CONTAINS target_role.name
)

UNWIND nodes(path_principal) + nodes(path_target) as n
OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL', provider_uid: $provider_uid})

RETURN path_principal, path_target,
    collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
\`\`\`

## Best Practices

1. **Always scope by provider**: Use \`{id: $provider_uid}\` on \`AWSAccount\` nodes. Use \`{_provider_id: $provider_id}\` on non-account nodes that need provider scoping (e.g., \`Internet\`).
2. **Chain all MATCHes from the root account node**: Every \`MATCH\` must connect to the \`aws\` variable. The \`Internet\` node is the only exception (uses \`OPTIONAL MATCH\` with \`_provider_id\`).
3. **Include Prowler findings**: Always add the \`OPTIONAL MATCH\` for \`ProwlerFinding\` nodes.
4. **Return distinct findings**: Use \`collect(DISTINCT pf)\` to avoid duplicates.
5. **Comment the query purpose**: Add inline comments explaining each \`MATCH\` clause.
6. **Use alternatives for unsupported features**: Replace \`=~\` with \`toLower()\` + exact match or \`CONTAINS\`/\`STARTS WITH\`. Replace \`reduce()\` with \`UNWIND\` + \`collect()\`.
`,
};
