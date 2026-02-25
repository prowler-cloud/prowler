# Prowler API Changelog

All notable changes to the **Prowler API** are documented in this file.

## [1.20.0] (Prowler UNRELEASED)

### 🚀 Added

- Finding group summaries and resources endpoints for hierarchical findings views [(#9961)](https://github.com/prowler-cloud/prowler/pull/9961)
- OpenStack provider support [(#10003)](https://github.com/prowler-cloud/prowler/pull/10003)
- PDF report for the CSA CCM compliance framework [(#10088)](https://github.com/prowler-cloud/prowler/pull/10088)
- `image` provider support for container image scanning [(#10128)](https://github.com/prowler-cloud/prowler/pull/10128)
- Attack Paths: Custom query and Cartography schema endpoints [(#10149)](https://github.com/prowler-cloud/prowler/pull/10149)

### 🔄 Changed

- Attack Paths: Queries definition now has short description and attribution [(#9983)](https://github.com/prowler-cloud/prowler/pull/9983)
- Attack Paths: Internet node is created while scan [(#9992)](https://github.com/prowler-cloud/prowler/pull/9992)
- Attack Paths: Add full paths set from [pathfinding.cloud](https://pathfinding.cloud/) [(#10008)](https://github.com/prowler-cloud/prowler/pull/10008)
- Support CSA CCM 4.0 for the AWS provider [(#10018)](https://github.com/prowler-cloud/prowler/pull/10018)
- Support CSA CCM 4.0 for the GCP provider [(#10042)](https://github.com/prowler-cloud/prowler/pull/10042)
- Support CSA CCM 4.0 for the Azure provider [(#10039)](https://github.com/prowler-cloud/prowler/pull/10039)
- Support CSA CCM 4.0 for the Oracle Cloud provider [(#10057)](https://github.com/prowler-cloud/prowler/pull/10057)
- Support CSA CCM 4.0 for the Alibaba Cloud provider [(#10061)](https://github.com/prowler-cloud/prowler/pull/10061)
- Attack Paths: Mark attack Paths scan as failed when Celery task fails outside job error handling [(#10065)](https://github.com/prowler-cloud/prowler/pull/10065)
- Attack Paths: Remove legacy per-scan `graph_database` and `is_graph_database_deleted` fields from AttackPathsScan model [(#10077)](https://github.com/prowler-cloud/prowler/pull/10077)
- Attack Paths: Add `graph_data_ready` field to decouple query availability from scan state [(#10089)](https://github.com/prowler-cloud/prowler/pull/10089)
- AI agent guidelines with TDD and testing skills references [(#9925)](https://github.com/prowler-cloud/prowler/pull/9925)
- Attack Paths: Upgrade Cartography from fork 0.126.1 to upstream 0.129.0 and Neo4j driver from 5.x to 6.x [(#10110)](https://github.com/prowler-cloud/prowler/pull/10110)
- Attack Paths: Query results now filtered by provider, preventing future cross-tenant and cross-provider data leakage [(#10118)](https://github.com/prowler-cloud/prowler/pull/10118)
- Attack Paths: Add private labels and properties in Attack Paths graphs for avoiding future overlapping with Cartography's ones [(#10124)](https://github.com/prowler-cloud/prowler/pull/10124)
- Attack Paths: Query endpoint executes them in read only mode [(#10140)](https://github.com/prowler-cloud/prowler/pull/10140)

### 🐞 Fixed

- Attack Paths: Orphaned temporary Neo4j databases are now cleaned up on scan failure and provider deletion [(#10101)](https://github.com/prowler-cloud/prowler/pull/10101)
- Attack Paths: scan no longer raises `DatabaseError` when provider is deleted mid-scan [(#10116)](https://github.com/prowler-cloud/prowler/pull/10116)
- Security Hub export retries transient replica conflicts without failing integrations [(#10144)](https://github.com/prowler-cloud/prowler/pull/10144)

### 🔐 Security

- Bump `Pillow` to 12.1.1 (CVE-2021-25289) [(#10027)](https://github.com/prowler-cloud/prowler/pull/10027)
- Remove safety ignore for CVE-2026-21226 (84420), fixed via `azure-core` 1.38.x [(#10110)](https://github.com/prowler-cloud/prowler/pull/10110)

---

## [1.19.3] (Prowler UNRELEASED)

### 🐞 Fixed

- GCP provider UID validation regex to allow domain prefixes [(#10078)](https://github.com/prowler-cloud/prowler/pull/10078)

---

## [1.19.2] (Prowler v5.18.2)

### 🐞 Fixed

- SAML role mapping now prevents removing the last MANAGE_ACCOUNT user [(#10007)](https://github.com/prowler-cloud/prowler/pull/10007)

---

## [1.19.0] (Prowler v5.18.0)

### 🚀 Added

- Cloudflare provider support [(#9907)](https://github.com/prowler-cloud/prowler/pull/9907)
- Attack Paths: Bedrock Code Interpreter and AttachRolePolicy privilege escalation queries [(#9885)](https://github.com/prowler-cloud/prowler/pull/9885)
- `provider_id` and `provider_id__in` filters for resources endpoints (`GET /resources` and `GET /resources/metadata/latest`) [(#9864)](https://github.com/prowler-cloud/prowler/pull/9864)
- Added memory optimizations for large compliance report generation [(#9444)](https://github.com/prowler-cloud/prowler/pull/9444)
- `GET /api/v1/resources/{id}/events` endpoint to retrieve AWS resource modification history from CloudTrail [(#9101)](https://github.com/prowler-cloud/prowler/pull/9101)
- Partial index on findings to speed up new failed findings queries [(#9904)](https://github.com/prowler-cloud/prowler/pull/9904)

### 🔄 Changed

- Lazy-load providers and compliance data to reduce API/worker startup memory and time [(#9857)](https://github.com/prowler-cloud/prowler/pull/9857)
- Attack Paths: Pinned Cartography to version `0.126.1`, adding AWS scans for SageMaker, CloudFront and Bedrock [(#9893)](https://github.com/prowler-cloud/prowler/issues/9893)
- Remove unused indexes [(#9904)](https://github.com/prowler-cloud/prowler/pull/9904)
- Attack Paths: Modified the behaviour of the Cartography scans to use the same Neo4j database per tenant, instead of individual databases per scans [(#9955)](https://github.com/prowler-cloud/prowler/pull/9955)

### 🐞 Fixed

- Attack Paths: `aws-security-groups-open-internet-facing` query returning no results due to incorrect relationship matching [(#9892)](https://github.com/prowler-cloud/prowler/pull/9892)

---

## [1.18.1] (Prowler v5.17.1)

### 🐞 Fixed

- Improve API startup process by `manage.py` argument detection [(#9856)](https://github.com/prowler-cloud/prowler/pull/9856)
- Deleting providers don't try to delete a `None` Neo4j database when an Attack Paths scan is scheduled [(#9858)](https://github.com/prowler-cloud/prowler/pull/9858)
- Use replica database for reading Findings to add them to the Attack Paths graph [(#9861)](https://github.com/prowler-cloud/prowler/pull/9861)
- Attack paths findings loading query to use streaming generator for O(batch_size) memory instead of O(total_findings) [(#9862)](https://github.com/prowler-cloud/prowler/pull/9862)
- Lazy load Neo4j driver [(#9868)](https://github.com/prowler-cloud/prowler/pull/9868)
- Use `Findings.all_objects` to avoid the `ActiveProviderPartitionedManager` [(#9869)](https://github.com/prowler-cloud/prowler/pull/9869)
- Lazy load Neo4j driver for workers only [(#9872)](https://github.com/prowler-cloud/prowler/pull/9872)
- Improve Cypher query for inserting Findings into Attack Paths scan graphs [(#9874)](https://github.com/prowler-cloud/prowler/pull/9874)
- Clear Neo4j database cache after Attack Paths scan and each API query [(#9877)](https://github.com/prowler-cloud/prowler/pull/9877)
- Deduplicated scheduled scans for long-running providers [(#9829)](https://github.com/prowler-cloud/prowler/pull/9829)

---

## [1.18.0] (Prowler v5.17.0)

### 🚀 Added

- `/api/v1/overviews/compliance-watchlist` endpoint to retrieve the compliance watchlist [(#9596)](https://github.com/prowler-cloud/prowler/pull/9596)
- AlibabaCloud provider support [(#9485)](https://github.com/prowler-cloud/prowler/pull/9485)
- `/api/v1/overviews/resource-groups` endpoint to retrieve an overview of resource groups based on finding severities [(#9694)](https://github.com/prowler-cloud/prowler/pull/9694)
- `group` filter for `GET /findings` and `GET /findings/metadata/latest` endpoints [(#9694)](https://github.com/prowler-cloud/prowler/pull/9694)
- `provider_id` and `provider_id__in` filter aliases for findings endpoints to enable consistent frontend parameter naming [(#9701)](https://github.com/prowler-cloud/prowler/pull/9701)
- Attack Paths: `/api/v1/attack-paths-scans` for AWS providers backed by Neo4j [(#9805)](https://github.com/prowler-cloud/prowler/pull/9805)

### 🔐 Security

- Django 5.1.15 (CVE-2025-64460, CVE-2025-13372), Werkzeug 3.1.4 (CVE-2025-66221), sqlparse 0.5.5 (PVE-2025-82038), fonttools 4.60.2 (CVE-2025-66034) [(#9730)](https://github.com/prowler-cloud/prowler/pull/9730)
- `safety` to `3.7.0` and `filelock` to `3.20.3` due to [Safety vulnerability 82754 (CVE-2025-68146)](https://data.safetycli.com/v/82754/97c/) [(#9816)](https://github.com/prowler-cloud/prowler/pull/9816)
- `pyasn1` to v0.6.2 to address [CVE-2026-23490](https://nvd.nist.gov/vuln/detail/CVE-2026-23490) [(#9818)](https://github.com/prowler-cloud/prowler/pull/9818)
- `django-allauth[saml]` to v65.13.0 to address [CVE-2025-65431](https://nvd.nist.gov/vuln/detail/CVE-2025-65431) [(#9575)](https://github.com/prowler-cloud/prowler/pull/9575)

---

## [1.17.1] (Prowler v5.16.1)

### 🔄 Changed

- Security Hub integration error when no regions [(#9635)](https://github.com/prowler-cloud/prowler/pull/9635)

### 🐞 Fixed

- Orphan scheduled scans caused by transaction isolation during provider creation [(#9633)](https://github.com/prowler-cloud/prowler/pull/9633)

---

## [1.17.0] (Prowler v5.16.0)

### 🚀 Added

- New endpoint to retrieve and overview of the categories based on finding severities [(#9529)](https://github.com/prowler-cloud/prowler/pull/9529)
- Endpoints `GET /findings` and `GET /findings/latests` can now use the category filter [(#9529)](https://github.com/prowler-cloud/prowler/pull/9529)
- Account id, alias and provider name to PDF reporting table [(#9574)](https://github.com/prowler-cloud/prowler/pull/9574)

### 🔄 Changed

- Endpoint `GET /overviews/attack-surfaces` no longer returns the related check IDs [(#9529)](https://github.com/prowler-cloud/prowler/pull/9529)
- OpenAI provider to only load chat-compatible models with tool calling support [(#9523)](https://github.com/prowler-cloud/prowler/pull/9523)
- Increased execution delay for the first scheduled scan tasks to 5 seconds[(#9558)](https://github.com/prowler-cloud/prowler/pull/9558)

### 🐞 Fixed

- Made `scan_id` a required filter in the compliance overview endpoint [(#9560)](https://github.com/prowler-cloud/prowler/pull/9560)
- Reduced unnecessary UPDATE resources operations by only saving when tag mappings change, lowering write load during scans [(#9569)](https://github.com/prowler-cloud/prowler/pull/9569)

---

## [1.16.1] (Prowler v5.15.1)

### 🐞 Fixed

- Race condition in scheduled scan creation by adding countdown to task [(#9516)](https://github.com/prowler-cloud/prowler/pull/9516)

## [1.16.0] (Prowler v5.15.0)

### 🚀 Added

- New endpoint to retrieve an overview of the attack surfaces [(#9309)](https://github.com/prowler-cloud/prowler/pull/9309)
- New endpoint `GET /api/v1/overviews/findings_severity/timeseries` to retrieve daily aggregated findings by severity level [(#9363)](https://github.com/prowler-cloud/prowler/pull/9363)
- Lighthouse AI support for Amazon Bedrock API key [(#9343)](https://github.com/prowler-cloud/prowler/pull/9343)
- Exception handler for provider deletions during scans [(#9414)](https://github.com/prowler-cloud/prowler/pull/9414)
- Support to use admin credentials through the read replica database [(#9440)](https://github.com/prowler-cloud/prowler/pull/9440)

### 🔄 Changed

- Error messages from Lighthouse celery tasks [(#9165)](https://github.com/prowler-cloud/prowler/pull/9165)
- Restore the compliance overview endpoint's mandatory filters [(#9338)](https://github.com/prowler-cloud/prowler/pull/9338)

---

## [1.15.2] (Prowler v5.14.2)

### 🐞 Fixed

- Unique constraint violation during compliance overviews task [(#9436)](https://github.com/prowler-cloud/prowler/pull/9436)
- Division by zero error in ENS PDF report when all requirements are manual [(#9443)](https://github.com/prowler-cloud/prowler/pull/9443)

---

## [1.15.1] (Prowler v5.14.1)

### 🐞 Fixed

- Fix typo in PDF reporting [(#9345)](https://github.com/prowler-cloud/prowler/pull/9345)
- Fix IaC provider initialization failure when mutelist processor is configured [(#9331)](https://github.com/prowler-cloud/prowler/pull/9331)
- Match logic for ThreatScore when counting findings [(#9348)](https://github.com/prowler-cloud/prowler/pull/9348)

---

## [1.15.0] (Prowler v5.14.0)

### 🚀 Added

- IaC (Infrastructure as Code) provider support for remote repositories [(#8751)](https://github.com/prowler-cloud/prowler/pull/8751)
- Extend `GET /api/v1/providers` with provider-type filters and optional pagination disable to support the new Overview filters [(#8975)](https://github.com/prowler-cloud/prowler/pull/8975)
- New endpoint to retrieve the number of providers grouped by provider type [(#8975)](https://github.com/prowler-cloud/prowler/pull/8975)
- Support for configuring multiple LLM providers [(#8772)](https://github.com/prowler-cloud/prowler/pull/8772)
- Support C5 compliance framework for Azure provider [(#9081)](https://github.com/prowler-cloud/prowler/pull/9081)
- Support for Oracle Cloud Infrastructure (OCI) provider [(#8927)](https://github.com/prowler-cloud/prowler/pull/8927)
- Support muting findings based on simple rules with custom reason [(#9051)](https://github.com/prowler-cloud/prowler/pull/9051)
- Support C5 compliance framework for the GCP provider [(#9097)](https://github.com/prowler-cloud/prowler/pull/9097)
- Support for Amazon Bedrock and OpenAI compatible providers in Lighthouse AI [(#8957)](https://github.com/prowler-cloud/prowler/pull/8957)
- Support PDF reporting for ENS compliance framework [(#9158)](https://github.com/prowler-cloud/prowler/pull/9158)
- Support PDF reporting for NIS2 compliance framework [(#9170)](https://github.com/prowler-cloud/prowler/pull/9170)
- Tenant-wide ThreatScore overview aggregation and snapshot persistence with backfill support [(#9148)](https://github.com/prowler-cloud/prowler/pull/9148)
- Added `metadata`, `details`, and `partition` attributes to `/resources` endpoint & `details`, and `partition` to `/findings` endpoint [(#9098)](https://github.com/prowler-cloud/prowler/pull/9098)
- Support for MongoDB Atlas provider [(#9167)](https://github.com/prowler-cloud/prowler/pull/9167)
- Support Prowler ThreatScore for the K8S provider [(#9235)](https://github.com/prowler-cloud/prowler/pull/9235)
- Enhanced compliance overview endpoint with provider filtering and latest scan aggregation [(#9244)](https://github.com/prowler-cloud/prowler/pull/9244)
- New endpoint `GET /api/v1/overview/regions` to retrieve aggregated findings data by region [(#9273)](https://github.com/prowler-cloud/prowler/pull/9273)

### 🔄 Changed

- Optimized database write queries for scan related tasks [(#9190)](https://github.com/prowler-cloud/prowler/pull/9190)
- Date filters are now optional for `GET /api/v1/overviews/services` endpoint; returns latest scan data by default [(#9248)](https://github.com/prowler-cloud/prowler/pull/9248)

### 🐞 Fixed

- Scans no longer fail when findings have UIDs exceeding 300 characters; such findings are now skipped with detailed logging [(#9246)](https://github.com/prowler-cloud/prowler/pull/9246)
- Updated unique constraint for `Provider` model to exclude soft-deleted entries, resolving duplicate errors when re-deleting providers [(#9054)](https://github.com/prowler-cloud/prowler/pull/9054)
- Removed compliance generation for providers without compliance frameworks [(#9208)](https://github.com/prowler-cloud/prowler/pull/9208)
- Refresh output report timestamps for each scan [(#9272)](https://github.com/prowler-cloud/prowler/pull/9272)
- Severity overview endpoint now ignores muted findings as expected [(#9283)](https://github.com/prowler-cloud/prowler/pull/9283)
- Fixed discrepancy between ThreatScore PDF report values and database calculations [(#9296)](https://github.com/prowler-cloud/prowler/pull/9296)

### 🔐 Security

- Django updated to the latest 5.1 security release, 5.1.14, due to problems with potential [SQL injection](https://github.com/prowler-cloud/prowler/security/dependabot/113) and [denial-of-service vulnerability](https://github.com/prowler-cloud/prowler/security/dependabot/114) [(#9176)](https://github.com/prowler-cloud/prowler/pull/9176)

---

## [1.14.1] (Prowler v5.13.1)

### 🐞 Fixed

- `/api/v1/overviews/providers` collapses data by provider type so the UI receives a single aggregated record per cloud family even when multiple accounts exist [(#9053)](https://github.com/prowler-cloud/prowler/pull/9053)
- Added retry logic to database transactions to handle Aurora read replica connection failures during scale-down events [(#9064)](https://github.com/prowler-cloud/prowler/pull/9064)
- Security Hub integrations stop failing when they read relationships via the replica by allowing replica relations and saving updates through the primary [(#9080)](https://github.com/prowler-cloud/prowler/pull/9080)

---

## [1.14.0] (Prowler v5.13.0)

### 🚀 Added

- Default JWT keys are generated and stored if they are missing from configuration [(#8655)](https://github.com/prowler-cloud/prowler/pull/8655)
- `compliance_name` for each compliance [(#7920)](https://github.com/prowler-cloud/prowler/pull/7920)
- Support C5 compliance framework for the AWS provider [(#8830)](https://github.com/prowler-cloud/prowler/pull/8830)
- Support for M365 Certificate authentication [(#8538)](https://github.com/prowler-cloud/prowler/pull/8538)
- API Key support [(#8805)](https://github.com/prowler-cloud/prowler/pull/8805)
- SAML role mapping protection for single-admin tenants to prevent accidental lockout [(#8882)](https://github.com/prowler-cloud/prowler/pull/8882)
- Support for `passed_findings` and `total_findings` fields in compliance requirement overview for accurate Prowler ThreatScore calculation [(#8582)](https://github.com/prowler-cloud/prowler/pull/8582)
- PDF reporting for Prowler ThreatScore [(#8867)](https://github.com/prowler-cloud/prowler/pull/8867)
- Database read replica support [(#8869)](https://github.com/prowler-cloud/prowler/pull/8869)
- Support Common Cloud Controls for AWS, Azure and GCP [(#8000)](https://github.com/prowler-cloud/prowler/pull/8000)
- Add `provider_id__in` filter support to findings and findings severity overview endpoints [(#8951)](https://github.com/prowler-cloud/prowler/pull/8951)

### 🔄 Changed

- Now the MANAGE_ACCOUNT permission is required to modify or read user permissions instead of MANAGE_USERS [(#8281)](https://github.com/prowler-cloud/prowler/pull/8281)
- Now at least one user with MANAGE_ACCOUNT permission is required in the tenant [(#8729)](https://github.com/prowler-cloud/prowler/pull/8729)

### 🔐 Security

- Django updated to the latest 5.1 security release, 5.1.13, due to problems with potential [SQL injection](https://github.com/prowler-cloud/prowler/security/dependabot/104) and [directory traversals](https://github.com/prowler-cloud/prowler/security/dependabot/103) [(#8842)](https://github.com/prowler-cloud/prowler/pull/8842)

---

## [1.13.2] (Prowler v5.12.3)

### 🐞 Fixed

- 500 error when deleting user [(#8731)](https://github.com/prowler-cloud/prowler/pull/8731)

---

## [1.13.1] (Prowler v5.12.2)

### 🔄 Changed

- Renamed compliance overview task queue to `compliance` [(#8755)](https://github.com/prowler-cloud/prowler/pull/8755)

### 🔐 Security

- Django updated to the latest 5.1 security release, 5.1.12, due to [problems](https://www.djangoproject.com/weblog/2025/sep/03/security-releases/) with potential SQL injection in FilteredRelation column aliases [(#8693)](https://github.com/prowler-cloud/prowler/pull/8693)

---

## [1.13.0] (Prowler v5.12.0)

### 🚀 Added

- Integration with JIRA, enabling sending findings to a JIRA project [(#8622)](https://github.com/prowler-cloud/prowler/pull/8622), [(#8637)](https://github.com/prowler-cloud/prowler/pull/8637)
- `GET /overviews/findings_severity` now supports `filter[status]` and `filter[status__in]` to aggregate by specific statuses (`FAIL`, `PASS`)[(#8186)](https://github.com/prowler-cloud/prowler/pull/8186)
- Throttling options for `/api/v1/tokens` using the `DJANGO_THROTTLE_TOKEN_OBTAIN` environment variable [(#8647)](https://github.com/prowler-cloud/prowler/pull/8647)

---

## [1.12.0] (Prowler v5.11.0)

### 🚀 Added

- Lighthouse support for OpenAI GPT-5 [(#8527)](https://github.com/prowler-cloud/prowler/pull/8527)
- Integration with Amazon Security Hub, enabling sending findings to Security Hub [(#8365)](https://github.com/prowler-cloud/prowler/pull/8365)
- Generate ASFF output for AWS providers with SecurityHub integration enabled [(#8569)](https://github.com/prowler-cloud/prowler/pull/8569)

### 🐞 Fixed

- GitHub provider always scans user instead of organization when using provider UID [(#8587)](https://github.com/prowler-cloud/prowler/pull/8587)

---

## [1.11.0] (Prowler v5.10.0)

### 🚀 Added

- Github provider support [(#8271)](https://github.com/prowler-cloud/prowler/pull/8271)
- Integration with Amazon S3, enabling storage and retrieval of scan data via S3 buckets [(#8056)](https://github.com/prowler-cloud/prowler/pull/8056)

### 🐞 Fixed

- Avoid sending errors to Sentry in M365 provider when user authentication fails [(#8420)](https://github.com/prowler-cloud/prowler/pull/8420)

---

## [1.10.2] (Prowler v5.9.2)

### 🔄 Changed

- Optimized queries for resources views [(#8336)](https://github.com/prowler-cloud/prowler/pull/8336)

---

## [v1.10.1] (Prowler v5.9.1)

### 🐞 Fixed

- Calculate failed findings during scans to prevent heavy database queries [(#8322)](https://github.com/prowler-cloud/prowler/pull/8322)

---

## [v1.10.0] (Prowler v5.9.0)

### 🚀 Added

- SSO with SAML support [(#8175)](https://github.com/prowler-cloud/prowler/pull/8175)
- `GET /resources/metadata`, `GET /resources/metadata/latest` and `GET /resources/latest` to expose resource metadata and latest scan results [(#8112)](https://github.com/prowler-cloud/prowler/pull/8112)

### 🔄 Changed

- `/processors` endpoints to post-process findings. Currently, only the Mutelist processor is supported to allow to mute findings.
- Optimized the underlying queries for resources endpoints [(#8112)](https://github.com/prowler-cloud/prowler/pull/8112)
- Optimized include parameters for resources view [(#8229)](https://github.com/prowler-cloud/prowler/pull/8229)
- Optimized overview background tasks [(#8300)](https://github.com/prowler-cloud/prowler/pull/8300)

### 🐞 Fixed

- Search filter for findings and resources [(#8112)](https://github.com/prowler-cloud/prowler/pull/8112)
- RBAC is now applied to `GET /overviews/providers` [(#8277)](https://github.com/prowler-cloud/prowler/pull/8277)

### 🔄 Changed

- `POST /schedules/daily` returns a `409 CONFLICT` if already created [(#8258)](https://github.com/prowler-cloud/prowler/pull/8258)

### 🔐 Security

- Enhanced password validation to enforce 12+ character passwords with special characters, uppercase, lowercase, and numbers [(#8225)](https://github.com/prowler-cloud/prowler/pull/8225)

---

## [v1.9.1] (Prowler v5.8.1)

### 🚀 Added

- Custom exception for provider connection errors during scans [(#8234)](https://github.com/prowler-cloud/prowler/pull/8234)

### 🔄 Changed

- Summary and overview tasks now use a dedicated queue and no longer propagate errors to compliance tasks [(#8214)](https://github.com/prowler-cloud/prowler/pull/8214)

### 🐞 Fixed

- Scan with no resources will not trigger legacy code for findings metadata [(#8183)](https://github.com/prowler-cloud/prowler/pull/8183)
- Invitation email comparison case-insensitive [(#8206)](https://github.com/prowler-cloud/prowler/pull/8206)

### ❌ Removed

- Validation of the provider's secret type during updates [(#8197)](https://github.com/prowler-cloud/prowler/pull/8197)

---

## [v1.9.0] (Prowler v5.8.0)

### 🚀 Added

- Support GCP Service Account key [(#7824)](https://github.com/prowler-cloud/prowler/pull/7824)
- `GET /compliance-overviews` endpoints to retrieve compliance metadata and specific requirements statuses [(#7877)](https://github.com/prowler-cloud/prowler/pull/7877)
- Lighthouse configuration support [(#7848)](https://github.com/prowler-cloud/prowler/pull/7848)

### 🔄 Changed

- Reworked `GET /compliance-overviews` to return proper requirement metrics [(#7877)](https://github.com/prowler-cloud/prowler/pull/7877)
- Optional `user` and `password` for M365 provider [(#7992)](https://github.com/prowler-cloud/prowler/pull/7992)

### 🐞 Fixed

- Scheduled scans are no longer deleted when their daily schedule run is disabled [(#8082)](https://github.com/prowler-cloud/prowler/pull/8082)

---

## [v1.8.5] (Prowler v5.7.5)

### 🐞 Fixed

- Normalize provider UID to ensure safe and unique export directory paths [(#8007)](https://github.com/prowler-cloud/prowler/pull/8007).
- Blank resource types in `/metadata` endpoints [(#8027)](https://github.com/prowler-cloud/prowler/pull/8027)

---

## [v1.8.4] (Prowler v5.7.4)

### ❌ Removed

- Reverted RLS transaction handling and DB custom backend [(#7994)](https://github.com/prowler-cloud/prowler/pull/7994)

---

## [v1.8.3] (Prowler v5.7.3)

### 🚀 Added

- Database backend to handle already closed connections [(#7935)](https://github.com/prowler-cloud/prowler/pull/7935)

### 🔄 Changed

- Renamed field encrypted_password to password for M365 provider [(#7784)](https://github.com/prowler-cloud/prowler/pull/7784)

### 🐞 Fixed

- Transaction persistence with RLS operations [(#7916)](https://github.com/prowler-cloud/prowler/pull/7916)
- Reverted the change `get_with_retry` to use the original `get` method for retrieving tasks [(#7932)](https://github.com/prowler-cloud/prowler/pull/7932)

---

## [v1.8.2] (Prowler v5.7.2)

### 🐞 Fixed

- Task lookup to use task_kwargs instead of task_args for scan report resolution [(#7830)](https://github.com/prowler-cloud/prowler/pull/7830)
- Kubernetes UID validation to allow valid context names [(#7871)](https://github.com/prowler-cloud/prowler/pull/7871)
- Connection status verification before launching a scan [(#7831)](https://github.com/prowler-cloud/prowler/pull/7831)
- Race condition when creating background tasks [(#7876)](https://github.com/prowler-cloud/prowler/pull/7876)
- Error when modifying or retrieving tenants due to missing user UUID in transaction context [(#7890)](https://github.com/prowler-cloud/prowler/pull/7890)

---

## [v1.8.1] (Prowler v5.7.1)

### 🐞 Fixed

- Added database index to improve performance on finding lookup [(#7800)](https://github.com/prowler-cloud/prowler/pull/7800)

---

## [v1.8.0] (Prowler v5.7.0)

### 🚀 Added

- Huge improvements to `/findings/metadata` and resource related filters for findings [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690)
- Improvements to `/overviews` endpoints [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690)
- Queue to perform backfill background tasks [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690)
- New endpoints to retrieve latest findings and metadata [(#7743)](https://github.com/prowler-cloud/prowler/pull/7743)
- Export support for Prowler ThreatScore in M365 [(7783)](https://github.com/prowler-cloud/prowler/pull/7783)

---

## [v1.7.0] (Prowler v5.6.0)

### 🚀 Added

- M365 as a new provider [(#7563)](https://github.com/prowler-cloud/prowler/pull/7563)
- `compliance/` folder and ZIP‐export functionality for all compliance reports [(#7653)](https://github.com/prowler-cloud/prowler/pull/7653)
- API endpoint to fetch and download any specific compliance file by name [(#7653)](https://github.com/prowler-cloud/prowler/pull/7653)

---

## [v1.6.0] (Prowler v5.5.0)

### 🚀 Added

- Support for developing new integrations [(#7167)](https://github.com/prowler-cloud/prowler/pull/7167)
- HTTP Security Headers [(#7289)](https://github.com/prowler-cloud/prowler/pull/7289)
- New endpoint to get the compliance overviews metadata [(#7333)](https://github.com/prowler-cloud/prowler/pull/7333)
- Support for muted findings [(#7378)](https://github.com/prowler-cloud/prowler/pull/7378)
- Missing fields to API findings and resources [(#7318)](https://github.com/prowler-cloud/prowler/pull/7318)

---

## [v1.5.4] (Prowler v5.4.4)

### 🐞 Fixed

- Bug with periodic tasks when trying to delete a provider [(#7466)](https://github.com/prowler-cloud/prowler/pull/7466)

---

## [v1.5.3] (Prowler v5.4.3)

### 🐞 Fixed

- Duplicated scheduled scans handling [(#7401)](https://github.com/prowler-cloud/prowler/pull/7401)
- Environment variable to configure the deletion task batch size [(#7423)](https://github.com/prowler-cloud/prowler/pull/7423)

---

## [v1.5.2] (Prowler v5.4.2)

### 🔄 Changed

- Refactored deletion logic and implemented retry mechanism for deletion tasks [(#7349)](https://github.com/prowler-cloud/prowler/pull/7349)

---

## [v1.5.1] (Prowler v5.4.1)

### 🐞 Fixed

- Handle response in case local files are missing [(#7183)](https://github.com/prowler-cloud/prowler/pull/7183)
- Race condition when deleting export files after the S3 upload [(#7172)](https://github.com/prowler-cloud/prowler/pull/7172)
- Handle exception when a provider has no secret in test connection [(#7283)](https://github.com/prowler-cloud/prowler/pull/7283)

---

## [v1.5.0] (Prowler v5.4.0)

### 🚀 Added

- Social login integration with Google and GitHub [(#6906)](https://github.com/prowler-cloud/prowler/pull/6906)
- API scan report system, now all scans launched from the API will generate a compressed file with the report in OCSF, CSV and HTML formats [(#6878)](https://github.com/prowler-cloud/prowler/pull/6878)
- Configurable Sentry integration [(#6874)](https://github.com/prowler-cloud/prowler/pull/6874)

### 🔄 Changed

- Optimized `GET /findings` endpoint to improve response time and size [(#7019)](https://github.com/prowler-cloud/prowler/pull/7019)

---

## [v1.4.0] (Prowler v5.3.0)

### 🔄 Changed

- Daily scheduled scan instances are now created beforehand with `SCHEDULED` state [(#6700)](https://github.com/prowler-cloud/prowler/pull/6700)
- Findings endpoints now require at least one date filter [(#6800)](https://github.com/prowler-cloud/prowler/pull/6800)
- Findings metadata endpoint received a performance improvement [(#6863)](https://github.com/prowler-cloud/prowler/pull/6863)
- Increased the allowed length of the provider UID for Kubernetes providers [(#6869)](https://github.com/prowler-cloud/prowler/pull/6869)

---
