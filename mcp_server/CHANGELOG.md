# Prowler MCP Server Changelog

All notable changes to the **Prowler MCP Server** are documented in this file.

<!-- changelog: release notes start -->

## [0.10.0] (Prowler v5.38.0)

### 🚀 Added

- Test foundation for the MCP server with shared fixtures, JSON:API builders, mocked HTTP transports and CI coverage reporting [(#12291)](https://github.com/prowler-cloud/prowler/pull/12291)
- Test coverage for the integrations tools and models, pinning the connection-check choreography and the Jira dispatch retry safety [(#12343)](https://github.com/prowler-cloud/prowler/pull/12343)
- Container images now ship an SBOM and build provenance as OCI attestations [(#12352)](https://github.com/prowler-cloud/prowler/pull/12352)

### 🔄 Changed

- `prowler_send_findings_to_jira` now reports `safe_to_retry` on every outcome, true only when Prowler knows no Jira work item was created: a dispatch the API refused is retryable, one that failed on the server or got no answer is not [(#12343)](https://github.com/prowler-cloud/prowler/pull/12343)
- `prowler_list_integrations` no longer requests the `configuration` it discards, now that the API tolerates a sparse fieldset without it [(#12343)](https://github.com/prowler-cloud/prowler/pull/12343)

### 🔐 Security

- Upgrade cryptography to 50.0.0, closing CVE-2026-69247 and CVE-2026-69249 [(#12356)](https://github.com/prowler-cloud/prowler/pull/12356)

---

## [0.9.1] (Prowler v5.37.1)

### 🔐 Security

- Bumped `fastmcp` and pinned `cryptography`, `joserfc`, `mcp` and `python-multipart`, clearing all 7 high-severity CVEs from the MCP image [(#12307)](https://github.com/prowler-cloud/prowler/pull/12307)

---

## [0.9.0] (Prowler v5.37.0)

### 🚀 Added

- Read-only user management tools `prowler_list_users`, `prowler_get_user`, and `prowler_get_current_user` for listing tenant users with their emails and identifying the authenticated user [(#12088)](https://github.com/prowler-cloud/prowler/pull/12088)
- RBAC role tools `prowler_list_roles`, `prowler_get_role`, `prowler_get_user_roles`, and `prowler_set_user_role` for browsing roles and setting the role a user holds [(#12088)](https://github.com/prowler-cloud/prowler/pull/12088)
- Integrations tools to manage Amazon S3, AWS Security Hub and Jira integrations, and to send findings to Jira [(#12138)](https://github.com/prowler-cloud/prowler/pull/12138)

### 🔄 Changed

- README now documents the Cloud-only `prowler_cloud_*` tools available on the hosted Prowler MCP (alerts, findings triage, scan scheduling, scan configurations), and corrects the Prowler Hub check count and the scan orchestration capabilities [(#12266)](https://github.com/prowler-cloud/prowler/pull/12266)

### 🐞 Fixed

- Memory leak in HTTP mode caused by streamable-HTTP sessions being retained for the process lifetime when clients never sent `DELETE /mcp`; the server now runs stateless [(#12235)](https://github.com/prowler-cloud/prowler/pull/12235)
- `prowler_list_integrations` failing with a 500 error on tenants with a Jira integration, caused by the request leaving `configuration` out of the sparse fieldset [(#12259)](https://github.com/prowler-cloud/prowler/pull/12259)

---

## [0.8.0] (Prowler v5.35.0)

### 🔄 Changed

- Core Prowler tool namespace from the `prowler_app_*` prefix to `prowler_*` [(#12017)](https://github.com/prowler-cloud/prowler/pull/12017)

---

## [0.7.2] (Prowler v5.28.1)

### 🐞 Fixed

- Preserve authorization header in HTTP mode [(#11366)](https://github.com/prowler-cloud/prowler/pull/11366)

---

## [0.7.1] (Prowler v5.28.0)

### 🔐 Security

- `fastmcp` from 2.14.0 to 3.2.4 for GHSA-5h2m-4q8j-pqpj, GHSA-rww4-4w9c-7733, and GHSA-vv7q-7jx5-f767, which also pulls fixed `jaraco.context`, `python-multipart`, `starlette`, and drops the vulnerable `lupa`/`urllib3` transitive deps [(#11284)](https://github.com/prowler-cloud/prowler/pull/11284)

---

## [0.7.0] (Prowler v5.27.0)

### 🚀 Added

- Finding Groups tools [(#11140)](https://github.com/prowler-cloud/prowler/pull/11140)

### 🔐 Security

- `cryptography` from 46.0.1 to 47.0.0 (transitive) for CVE-2026-39892 and CVE-2026-26007 / CVE-2026-34073 [(#10978)](https://github.com/prowler-cloud/prowler/pull/10978)

---

## [0.6.0] (Prowler v5.23.0)

### 🚀 Added

- Resource events tool to get timeline for a resource (who, what, when) [(#10412)](https://github.com/prowler-cloud/prowler/pull/10412)

### 🔄 Changed

- Pin `httpx` dependency to exact version for reproducible installs [(#10593)](https://github.com/prowler-cloud/prowler/pull/10593)

### 🔐 Security

- `authlib` bumped from 1.6.5 to 1.6.9 to fix CVE-2026-28802 (JWT `alg: none` validation bypass) [(#10579)](https://github.com/prowler-cloud/prowler/pull/10579)

---

## [0.5.0] (Prowler v5.21.0)

### 🚀 Added

- Attack Path tool to get Neo4j DB schema [(#10321)](https://github.com/prowler-cloud/prowler/pull/10321)

---

## [0.4.0] (Prowler v5.19.0)

### 🚀 Added

- Attack Paths tools to list scans, discover queries, and run Cypher queries against Neo4j [(#10145)](https://github.com/prowler-cloud/prowler/pull/10145)

---

## [0.3.0] (Prowler v5.16.0)

### 🚀 Added

- MCP Server tools for Prowler Compliance Framework Management [(#9568)](https://github.com/prowler-cloud/prowler/pull/9568)

### 🔄 Changed

- API base URL environment variable to include complete path [(#9542)](https://github.com/prowler-cloud/prowler/pull/9542)
- Prowler Hub and Docs tools format standardized for AI optimization [(#9578)](https://github.com/prowler-cloud/prowler/pull/9578)

---

## [0.2.0] (Prowler v5.15.0)

### 🚀 Added

- MCP Server tools for Prowler Findings and Compliance, replacing all Prowler App MCP tools [(#9300)](https://github.com/prowler-cloud/prowler/pull/9300)
- MCP Server tools for Prowler Providers Management [(#9350)](https://github.com/prowler-cloud/prowler/pull/9350)
- MCP Server tools for Prowler Resources Management [(#9380)](https://github.com/prowler-cloud/prowler/pull/9380)
- MCP Server tools for Prowler Scans Management [(#9509)](https://github.com/prowler-cloud/prowler/pull/9509)
- MCP Server tools for Prowler Muting Management [(#9510)](https://github.com/prowler-cloud/prowler/pull/9510)

---

## [0.1.1] (Prowler v5.14.0)

### 🐞 Fixed

- Documentation MCP Server to return list of dictionaries [(#9205)](https://github.com/prowler-cloud/prowler/pull/9205)

---

## [0.1.0] (Prowler v5.13.0)

### 🚀 Added

- Initial release of Prowler MCP Server [(#8695)](https://github.com/prowler-cloud/prowler/pull/8695)
- Appropriate user-agent in requests [(#8724)](https://github.com/prowler-cloud/prowler/pull/8724)
- Basic logger functionality [(#8740)](https://github.com/prowler-cloud/prowler/pull/8740)
- MCP Server for Prowler Cloud and Prowler App (Self-Managed) APIs [(#8744)](https://github.com/prowler-cloud/prowler/pull/8744)
- HTTP transport support [(#8784)](https://github.com/prowler-cloud/prowler/pull/8784)
- MCP Server for Prowler Documentation [(#8795)](https://github.com/prowler-cloud/prowler/pull/8795)
- API key support for STDIO mode and enhanced HTTP mode authentication [(#8823)](https://github.com/prowler-cloud/prowler/pull/8823)
- Health check endpoint [(#8905)](https://github.com/prowler-cloud/prowler/pull/8905)
- Prowler Documentation MCP Server updated to use Mintlify API [(#8916)](https://github.com/prowler-cloud/prowler/pull/8916)
- Custom production deployment using uvicorn [(#8958)](https://github.com/prowler-cloud/prowler/pull/8958)
