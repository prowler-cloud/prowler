# Prowler SDK Changelog

All notable changes to the **Prowler SDK** are documented in this file.

## [5.17.0] (Prowler UNRELEASED)

### Added
- Add Prowler ThreatScore for the Alibaba Cloud provider [(#9511)](https://github.com/prowler-cloud/prowler/pull/9511)
- `compute_instance_group_multiple_zones` check for GCP provider [(#9566)](https://github.com/prowler-cloud/prowler/pull/9566)

### Changed
- Update AWS Step Functions service metadata to new format [(#9432)](https://github.com/prowler-cloud/prowler/pull/9432)
- Update AWS Route 53 service metadata to new format [(#9406)](https://github.com/prowler-cloud/prowler/pull/9406)
- Update AWS SQS service metadata to new format [(#9429)](https://github.com/prowler-cloud/prowler/pull/9429)
- Update AWS Shield service metadata to new format [(#9427)](https://github.com/prowler-cloud/prowler/pull/9427)
- Update AWS Secrets Manager service metadata to new format [(#9408)](https://github.com/prowler-cloud/prowler/pull/9408)
- Update GCP GKE service metadata to new format [(#9645)](https://github.com/prowler-cloud/prowler/pull/9645)


---

## [5.16.0] (Prowler v5.16.0)

### Added

- `privilege-escalation` and `ec2-imdsv1` categories for AWS checks [(#9537)](https://github.com/prowler-cloud/prowler/pull/9537)
- Supported IaC formats and scanner documentation for the IaC provider [(#9553)](https://github.com/prowler-cloud/prowler/pull/9553)

### Changed

- Update AWS Glue service metadata to new format [(#9258)](https://github.com/prowler-cloud/prowler/pull/9258)
- Update AWS Kafka service metadata to new format [(#9261)](https://github.com/prowler-cloud/prowler/pull/9261)
- Update AWS KMS service metadata to new format [(#9263)](https://github.com/prowler-cloud/prowler/pull/9263)
- Update AWS MemoryDB service metadata to new format [(#9266)](https://github.com/prowler-cloud/prowler/pull/9266)
- Update AWS Inspector v2 service metadata to new format [(#9260)](https://github.com/prowler-cloud/prowler/pull/9260)
- Update AWS Service Catalog service metadata to new format [(#9410)](https://github.com/prowler-cloud/prowler/pull/9410)
- Update AWS SNS service metadata to new format [(#9428)](https://github.com/prowler-cloud/prowler/pull/9428)
- Update AWS Trusted Advisor service metadata to new format [(#9435)](https://github.com/prowler-cloud/prowler/pull/9435)
- Update AWS WAF service metadata to new format [(#9480)](https://github.com/prowler-cloud/prowler/pull/9480)
- Update AWS WAF v2 service metadata to new format [(#9481)](https://github.com/prowler-cloud/prowler/pull/9481)

### Fixed
- Fix typo `trustboundaries` category to `trust-boundaries` [(#9536)](https://github.com/prowler-cloud/prowler/pull/9536)
- Fix incorrect `bedrock-agent` regional availability, now using official AWS docs instead of copying from `bedrock`
- Store MongoDB Atlas provider regions as lowercase [(#9554)](https://github.com/prowler-cloud/prowler/pull/9554)
- Store GCP Cloud Storage bucket regions as lowercase [(#9567)](https://github.com/prowler-cloud/prowler/pull/9567)

---

## [5.15.1] (Prowler v5.15.1)

### Fixed
- Fix false negative in AWS `apigateway_restapi_logging_enabled` check by refining stage logging evaluation to ensure logging level is not set to "OFF" [(#9304)](https://github.com/prowler-cloud/prowler/pull/9304)

---

## [5.15.0] (Prowler v5.15.0)

### Added
- `cloudstorage_uses_vpc_service_controls` check for GCP provider [(#9256)](https://github.com/prowler-cloud/prowler/pull/9256)
- Alibaba Cloud provider with CIS 2.0 benchmark [(#9329)](https://github.com/prowler-cloud/prowler/pull/9329)
- `repository_immutable_releases_enabled` check for GitHub provider [(#9162)](https://github.com/prowler-cloud/prowler/pull/9162)
- `compute_instance_preemptible_vm_disabled` check for GCP provider [(#9342)](https://github.com/prowler-cloud/prowler/pull/9342)
- `compute_instance_automatic_restart_enabled` check for GCP provider [(#9271)](https://github.com/prowler-cloud/prowler/pull/9271)
- `compute_instance_deletion_protection_enabled` check for GCP provider [(#9358)](https://github.com/prowler-cloud/prowler/pull/9358)
- Add needed changes to AlibabaCloud provider from the API [(#9485)](https://github.com/prowler-cloud/prowler/pull/9485)
- Update SOC2 - Azure with Processing Integrity requirements [(#9463)](https://github.com/prowler-cloud/prowler/pull/9463)
- Update SOC2 - GCP with Processing Integrity requirements [(#9464)](https://github.com/prowler-cloud/prowler/pull/9464)
- Update SOC2 - AWS with Processing Integrity requirements [(#9462)](https://github.com/prowler-cloud/prowler/pull/9462)
- RBI Cyber Security Framework compliance for Azure provider [(#8822)](https://github.com/prowler-cloud/prowler/pull/8822)

### Changed
- Update AWS Macie service metadata to new format [(#9265)](https://github.com/prowler-cloud/prowler/pull/9265)
- Update AWS Lightsail service metadata to new format [(#9264)](https://github.com/prowler-cloud/prowler/pull/9264)
- Update AWS GuardDuty service metadata to new format [(#9259)](https://github.com/prowler-cloud/prowler/pull/9259)
- Update AWS Network Firewall service metadata to new format [(#9382)](https://github.com/prowler-cloud/prowler/pull/9382)
- Update AWS MQ service metadata to new format [(#9267)](https://github.com/prowler-cloud/prowler/pull/9267)
- Update AWS Macie service metadata to new format [(#9265)](https://github.com/prowler-cloud/prowler/pull/9265)
- Update AWS Lightsail service metadata to new format [(#9264)](https://github.com/prowler-cloud/prowler/pull/9264)

### Fixed
- Fix duplicate requirement IDs in ISO 27001:2013 AWS compliance framework by adding unique letter suffixes
- Removed incorrect threat-detection category from checks metadata [(#9489)](https://github.com/prowler-cloud/prowler/pull/9489)
- GCP `cloudstorage_uses_vpc_service_controls` check to handle VPC Service Controls blocked API access [(#9478)](https://github.com/prowler-cloud/prowler/pull/9478)

---

## [5.14.2] (Prowler v5.14.2)

### Fixed
- Custom check folder metadata validation [(#9335)](https://github.com/prowler-cloud/prowler/pull/9335)
- Pin `alibabacloud-gateway-oss-util` to version 0.0.3 to address missing dependency [(#9487)](https://github.com/prowler-cloud/prowler/pull/9487)

---

## [5.14.1] (Prowler v5.14.1)

### Fixed
- `sharepoint_external_sharing_managed` check to handle external sharing disabled at organization level [(#9298)](https://github.com/prowler-cloud/prowler/pull/9298)
- Support multiple Exchange mailbox policies in M365 `exchange_mailbox_policy_additional_storage_restricted` check [(#9241)](https://github.com/prowler-cloud/prowler/pull/9241)

---

## [5.14.0] (Prowler v5.14.0)

### Added
- GitHub provider check `organization_default_repository_permission_strict` [(#8785)](https://github.com/prowler-cloud/prowler/pull/8785)
- Add OCI mapping to scan and check classes [(#8927)](https://github.com/prowler-cloud/prowler/pull/8927)
- `codepipeline_project_repo_private` check for AWS provider [(#5915)](https://github.com/prowler-cloud/prowler/pull/5915)
- `cloudstorage_bucket_versioning_enabled` check for GCP provider [(#9014)](https://github.com/prowler-cloud/prowler/pull/9014)
- `cloudstorage_bucket_soft_delete_enabled` check for GCP provider [(#9028)](https://github.com/prowler-cloud/prowler/pull/9028)
- `cloudstorage_bucket_logging_enabled` check for GCP provider [(#9091)](https://github.com/prowler-cloud/prowler/pull/9091)
- `cloudstorage_audit_logs_enabled` check for GCP provider [(#9220)](https://github.com/prowler-cloud/prowler/pull/9220)
- `cloudstorage_bucket_sufficient_retention_period` check for GCP provider [(#9149)](https://github.com/prowler-cloud/prowler/pull/9149)
- C5 compliance framework for Azure provider [(#9081)](https://github.com/prowler-cloud/prowler/pull/9081)
- C5 compliance framework for the GCP provider [(#9097)](https://github.com/prowler-cloud/prowler/pull/9097)
- `organization_repository_creation_limited` check for GitHub provider [(#8844)](https://github.com/prowler-cloud/prowler/pull/8844)
- HIPAA compliance framework for the GCP provider [(#8955)](https://github.com/prowler-cloud/prowler/pull/8955)
- Support PDF reporting for ENS compliance framework [(#9158)](https://github.com/prowler-cloud/prowler/pull/9158)
- PDF reporting for NIS2 compliance framework [(#9170)](https://github.com/prowler-cloud/prowler/pull/9170)
- Add organization ID parameter for MongoDB Atlas provider [(#9167)](https://github.com/prowler-cloud/prowler/pull/9167)
- Add multiple compliance improvements [(#9145)](https://github.com/prowler-cloud/prowler/pull/9145)
- Added validation for invalid checks, services, and categories in `load_checks_to_execute` function [(#8971)](https://github.com/prowler-cloud/prowler/pull/8971)
- NIST CSF 2.0 compliance framework for the AWS provider [(#9185)](https://github.com/prowler-cloud/prowler/pull/9185)
- Add FedRAMP 20x KSI Low for AWS, Azure and GCP [(#9198)](https://github.com/prowler-cloud/prowler/pull/9198)
- Add verification for provider ID in MongoDB Atlas provider [(#9211)](https://github.com/prowler-cloud/prowler/pull/9211)
- Add Prowler ThreatScore for the K8S provider [(#9235)](https://github.com/prowler-cloud/prowler/pull/9235)
- Add `postgresql_flexible_server_entra_id_authentication_enabled` check for Azure provider [(#8764)](https://github.com/prowler-cloud/prowler/pull/8764)
- Add branch name to IaC provider region [(#9296)](https://github.com/prowler-cloud/prowler/pull/9295)

### Changed
- Update AWS Direct Connect service metadata to new format [(#8855)](https://github.com/prowler-cloud/prowler/pull/8855)
- Update AWS DRS service metadata to new format [(#8870)](https://github.com/prowler-cloud/prowler/pull/8870)
- Update AWS DynamoDB service metadata to new format [(#8871)](https://github.com/prowler-cloud/prowler/pull/8871)
- Update AWS CloudWatch service metadata to new format [(#8848)](https://github.com/prowler-cloud/prowler/pull/8848)
- Update AWS EMR service metadata to new format [(#9002)](https://github.com/prowler-cloud/prowler/pull/9002)
- Update AWS EKS service metadata to new format [(#8890)](https://github.com/prowler-cloud/prowler/pull/8890)
- Update AWS Elastic Beanstalk service metadata to new format [(#8934)](https://github.com/prowler-cloud/prowler/pull/8934)
- Update AWS ElastiCache service metadata to new format [(#8933)](https://github.com/prowler-cloud/prowler/pull/8933)
- Update Kubernetes etcd service metadata to new format [(#9096)](https://github.com/prowler-cloud/prowler/pull/9096)
- Update MongoDB Atlas projects service metadata to new format [(#9093)](https://github.com/prowler-cloud/prowler/pull/9093)
- Update GitHub Organization service metadata to new format [(#9094)](https://github.com/prowler-cloud/prowler/pull/9094)
- Update AWS CodeBuild service metadata to new format [(#8851)](https://github.com/prowler-cloud/prowler/pull/8851)
- Update GCP Artifact Registry service metadata to new format [(#9088)](https://github.com/prowler-cloud/prowler/pull/9088)
- Update AWS EFS service metadata to new format [(#8889)](https://github.com/prowler-cloud/prowler/pull/8889)
- Update AWS EventBridge service metadata to new format [(#9003)](https://github.com/prowler-cloud/prowler/pull/9003)
- Update AWS Firehose service metadata to new format [(#9004)](https://github.com/prowler-cloud/prowler/pull/9004)
- Update AWS FMS service metadata to new format [(#9005)](https://github.com/prowler-cloud/prowler/pull/9005)
- Update AWS FSx service metadata to new format [(#9006)](https://github.com/prowler-cloud/prowler/pull/9006)
- Update AWS Glacier service metadata to new format [(#9007)](https://github.com/prowler-cloud/prowler/pull/9007)
- Update oraclecloud analytics service metadata to new format [(#9114)](https://github.com/prowler-cloud/prowler/pull/9114)
- Update AWS ELB service metadata to new format [(#8935)](https://github.com/prowler-cloud/prowler/pull/8935)
- Update AWS CodeArtifact service metadata to new format [(#8850)](https://github.com/prowler-cloud/prowler/pull/8850)
- Rename OCI provider to oraclecloud with oci alias [(#9126)](https://github.com/prowler-cloud/prowler/pull/9126)
- Remove unnecessary tests for M365_PowerShell module [(#9204)](https://github.com/prowler-cloud/prowler/pull/9204)
- Update AWS ELB v2 service metadata to new format [(#9001)](https://github.com/prowler-cloud/prowler/pull/9001)
- Update oraclecloud cloudguard service metadata to new format [(#9223)](https://github.com/prowler-cloud/prowler/pull/9223)
- Update oraclecloud blockstorage service metadata to new format [(#9222)](https://github.com/prowler-cloud/prowler/pull/9222)
- Update oraclecloud audit service metadata to new format [(#9221)](https://github.com/prowler-cloud/prowler/pull/9221)
- Raise ASFF output error for non-AWS providers [(#9225)](https://github.com/prowler-cloud/prowler/pull/9225)
- Update AWS ECR service metadata to new format [(#8872)](https://github.com/prowler-cloud/prowler/pull/8872)
- Update AWS ECS service metadata to new format [(#8888)](https://github.com/prowler-cloud/prowler/pull/8888)
- Update AWS Kinesis service metadata to new format [(#9262)](https://github.com/prowler-cloud/prowler/pull/9262)
- Update AWS DocumentDB service metadata to new format [(#8862)](https://github.com/prowler-cloud/prowler/pull/8862)


### Fixed
- Check `check_name` has no `resource_name` error for GCP provider [(#9169)](https://github.com/prowler-cloud/prowler/pull/9169)
- Depth Truncation and parsing error in PowerShell queries [(#9181)](https://github.com/prowler-cloud/prowler/pull/9181)
- False negative in `iam_role_cross_service_confused_deputy_prevention` check [(#9213)](https://github.com/prowler-cloud/prowler/pull/9213)
- Fix M365 Teams `--sp-env-auth` connection error and enhanced timeout logging [(#9191)](https://github.com/prowler-cloud/prowler/pull/9191)
- Rename `get_oci_assessment_summary` to `get_oraclecloud_assessment_summary` in HTML output [(#9200)](https://github.com/prowler-cloud/prowler/pull/9200)
- Fix Validation and other errors in Azure provider [(#8915)](https://github.com/prowler-cloud/prowler/pull/8915)
- Update documentation URLs from docs.prowler.cloud to docs.prowler.com [(#9240)](https://github.com/prowler-cloud/prowler/pull/9240)
- Refresh output report timestamps for each scan [(#9272)](https://github.com/prowler-cloud/prowler/pull/9272)
- Fix file name parsing for checks on Windows [(#9268)](https://github.com/prowler-cloud/prowler/pull/9268)
- Remove typo for Prowler ThreatScore - M365 [(#9274)](https://github.com/prowler-cloud/prowler/pull/9274)
- Point HTML logo to the one present in the Github repository [(#9282)](https://github.com/prowler-cloud/prowler/pull/9282)

---

## [5.13.1] (Prowler v5.13.1)

### Fixed
- Add `resource_name` for checks under `logging` for the GCP provider [(#9023)](https://github.com/prowler-cloud/prowler/pull/9023)
- Fix `ec2_instance_with_outdated_ami` check to handle None AMIs [(#9046)](https://github.com/prowler-cloud/prowler/pull/9046)
- Handle timestamp when transforming compliance findings in CCC [(#9042)](https://github.com/prowler-cloud/prowler/pull/9042)
- Update `resource_id` for admincenter service and avoid unnecessary msgraph requests [(#9019)](https://github.com/prowler-cloud/prowler/pull/9019)
- Fix `firehose_stream_encrypted_at_rest` description and findings clarity [(#9142)](https://github.com/prowler-cloud/prowler/pull/9142)

---

### Changed
- Adapt IaC provider to be used in the Prowler App [(#8751)](https://github.com/prowler-cloud/prowler/pull/8751)

---

## [5.13.0] (Prowler v5.13.0)

### Added
- Support for AdditionalURLs in outputs [(#8651)](https://github.com/prowler-cloud/prowler/pull/8651)
- Support for markdown metadata fields in Dashboard [(#8667)](https://github.com/prowler-cloud/prowler/pull/8667)
- `ec2_instance_with_outdated_ami` check for AWS provider [(#6910)](https://github.com/prowler-cloud/prowler/pull/6910)
- LLM provider using `promptfoo` [(#8555)](https://github.com/prowler-cloud/prowler/pull/8555)
- Documentation for renaming checks [(#8717)](https://github.com/prowler-cloud/prowler/pull/8717)
- Add explicit "name" field for each compliance framework and include "FRAMEWORK" and "NAME" in CSV output [(#7920)](https://github.com/prowler-cloud/prowler/pull/7920)
- Add C5 compliance framework for the AWS provider [(#8830)](https://github.com/prowler-cloud/prowler/pull/8830)
- Equality validation for CheckID, filename and classname [(#8690)](https://github.com/prowler-cloud/prowler/pull/8690)
- Improve logging for Security Hub integration [(#8608)](https://github.com/prowler-cloud/prowler/pull/8608)
- Oracle Cloud provider with CIS 3.0 benchmark [(#8893)](https://github.com/prowler-cloud/prowler/pull/8893)
- Support for Atlassian Document Format (ADF) in Jira integration [(#8878)](https://github.com/prowler-cloud/prowler/pull/8878)
- Add Common Cloud Controls for AWS, Azure and GCP [(#8000)](https://github.com/prowler-cloud/prowler/pull/8000)
- Improve Provider documentation guide [(#8430)](https://github.com/prowler-cloud/prowler/pull/8430)
- `cloudstorage_bucket_lifecycle_management_enabled` check for GCP provider [(#8936)](https://github.com/prowler-cloud/prowler/pull/8936)

### Changed

- Update AWS Neptune service metadata to new format [(#8494)](https://github.com/prowler-cloud/prowler/pull/8494)
- Update AWS Config service metadata to new format [(#8641)](https://github.com/prowler-cloud/prowler/pull/8641)
- Update AWS Account service metadata to new format [(#8715)](https://github.com/prowler-cloud/prowler/pull/8715)
- Update AWS AccessAnalyzer service metadata to new format [(#8688)](https://github.com/prowler-cloud/prowler/pull/8688)
- Update AWS Api Gateway V2 service metadata to new format [(#8719)](https://github.com/prowler-cloud/prowler/pull/8719)
- Update AWS AppSync service metadata to new format [(#8721)](https://github.com/prowler-cloud/prowler/pull/8721)
- Update AWS ACM service metadata to new format [(#8716)](https://github.com/prowler-cloud/prowler/pull/8716)
- HTML output now properly renders markdown syntax in Risk and Recommendation fields [(#8727)](https://github.com/prowler-cloud/prowler/pull/8727)
- Update `moto` dependency from 5.0.28 to 5.1.11 [(#7100)](https://github.com/prowler-cloud/prowler/pull/7100)
- Update AWS AppStream service metadata to new format [(#8789)](https://github.com/prowler-cloud/prowler/pull/8789)
- Update AWS API Gateway service metadata to new format [(#8788)](https://github.com/prowler-cloud/prowler/pull/8788)
- Update AWS Athena service metadata to new format [(#8790)](https://github.com/prowler-cloud/prowler/pull/8790)
- Update AWS CloudTrail service metadata to new format [(#8831)](https://github.com/prowler-cloud/prowler/pull/8831)
- Update AWS Auto Scaling service metadata to new format [(#8824)](https://github.com/prowler-cloud/prowler/pull/8824)
- Update AWS Backup service metadata to new format [(#8826)](https://github.com/prowler-cloud/prowler/pull/8826)
- Update AWS CloudFormation service metadata to new format [(#8828)](https://github.com/prowler-cloud/prowler/pull/8828)
- Update AWS Lambda service metadata to new format [(#8825)](https://github.com/prowler-cloud/prowler/pull/8825)
- Update AWS DLM service metadata to new format [(#8860)](https://github.com/prowler-cloud/prowler/pull/8860)
- Update AWS DMS service metadata to new format [(#8861)](https://github.com/prowler-cloud/prowler/pull/8861)
- Update AWS Directory Service service metadata to new format [(#8859)](https://github.com/prowler-cloud/prowler/pull/8859)
- Update AWS CloudFront service metadata to new format [(#8829)](https://github.com/prowler-cloud/prowler/pull/8829)
- Deprecate user authentication for M365 provider [(#8865)](https://github.com/prowler-cloud/prowler/pull/8865)


### Fixed
- Fix SNS topics showing empty AWS_ResourceID in Quick Inventory output [(#8762)](https://github.com/prowler-cloud/prowler/issues/8762)
- Fix HTML Markdown output for long strings [(#8803)](https://github.com/prowler-cloud/prowler/pull/8803)
- Prowler ThreatScore scoring calculation CLI [(#8582)](https://github.com/prowler-cloud/prowler/pull/8582)
- Add missing attributes for Mitre Attack AWS, Azure and GCP [(#8907)](https://github.com/prowler-cloud/prowler/pull/8907)
- Fix KeyError in CloudSQL and Monitoring services in GCP provider [(#8909)](https://github.com/prowler-cloud/prowler/pull/8909)
- Fix Value Errors in Entra service for M365 provider [(#8919)](https://github.com/prowler-cloud/prowler/pull/8919)
- Fix ResourceName in GCP provider [(#8928)](https://github.com/prowler-cloud/prowler/pull/8928)
- Fix KeyError in `elb_ssl_listeners_use_acm_certificate` check and handle None cluster version in `eks_cluster_uses_a_supported_version` check [(#8791)](https://github.com/prowler-cloud/prowler/pull/8791)
- Fix file extension parsing for compliance reports [(#8791)](https://github.com/prowler-cloud/prowler/pull/8791)
- Added user pagination to Entra and Admincenter services [(#8858)](https://github.com/prowler-cloud/prowler/pull/8858)

---

## [5.12.1] (Prowler v5.12.1)

### Fixed
- Replaced old check id with new ones for compliance files [(#8682)](https://github.com/prowler-cloud/prowler/pull/8682)
- `firehose_stream_encrypted_at_rest` check false positives and new api call in kafka service [(#8599)](https://github.com/prowler-cloud/prowler/pull/8599)
- Replace defender rules policies key to use old name [(#8702)](https://github.com/prowler-cloud/prowler/pull/8702)

---

## [5.12.0] (Prowler v5.12.0)

### Added
- Add more fields for the Jira ticket and handle custom fields errors [(#8601)](https://github.com/prowler-cloud/prowler/pull/8601)
- Support labels on Jira tickets [(#8603)](https://github.com/prowler-cloud/prowler/pull/8603)
- Add finding url and tenant info inside Jira tickets [(#8607)](https://github.com/prowler-cloud/prowler/pull/8607)
- Get Jira Project's metadata [(#8630)](https://github.com/prowler-cloud/prowler/pull/8630)
- Get Jira projects from test_connection [(#8634)](https://github.com/prowler-cloud/prowler/pull/8634)
- `AdditionalUrls` field in CheckMetadata [(#8590)](https://github.com/prowler-cloud/prowler/pull/8590)
- Support color for MANUAL finidngs in Jira tickets [(#8642)](https://github.com/prowler-cloud/prowler/pull/8642)
- `--excluded-checks-file` flag [(#8301)](https://github.com/prowler-cloud/prowler/pull/8301)
- Send finding in Jira integration with the needed values [(#8648)](https://github.com/prowler-cloud/prowler/pull/8648)
- Add language enforcement for Jira requests [(#8674)](https://github.com/prowler-cloud/prowler/pull/8674)
- MongoDB Atlas provider with 10 security checks [(#8312)](https://github.com/prowler-cloud/prowler/pull/8312)
  - `clusters_authentication_enabled` - Ensure clusters have authentication enabled
  - `clusters_backup_enabled` - Ensure clusters have backup enabled
  - `clusters_encryption_at_rest_enabled` - Ensure clusters have encryption at rest enabled
  - `clusters_tls_enabled` - Ensure clusters have TLS authentication required
  - `organizations_api_access_list_required` - Ensure organization requires API access list
  - `organizations_mfa_required` - Ensure organization requires MFA
  - `organizations_security_contact_defined` - Ensure organization has security contact defined
  - `organizations_service_account_secrets_expiration` - Ensure organization has maximum period expiration for service account secrets
  - `projects_auditing_enabled` - Ensure database auditing is enabled
  - `projects_network_access_list_exposed_to_internet` - Ensure project network access list is not exposed to internet

### Changed
- Rename ftp and mongo checks to follow pattern `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_*` [(#8293)](https://github.com/prowler-cloud/prowler/pull/8293)

### Fixed
- Renamed `AdditionalUrls` to `AdditionalURLs` field in CheckMetadata [(#8639)](https://github.com/prowler-cloud/prowler/pull/8639)
- TypeError from Python 3.9 in Security Hub module by updating type annotations [(#8619)](https://github.com/prowler-cloud/prowler/pull/8619)
- KeyError when SecurityGroups field is missing in MemoryDB check [(#8666)](https://github.com/prowler-cloud/prowler/pull/8666)
- NoneType error in Opensearch, Firehose and Cognito checks [(#8670)](https://github.com/prowler-cloud/prowler/pull/8670)

---

## [5.11.0] (Prowler v5.11.0)

### Added
- Certificate authentication for M365 provider [(#8404)](https://github.com/prowler-cloud/prowler/pull/8404)
- `vm_sufficient_daily_backup_retention_period` check for Azure provider [(#8200)](https://github.com/prowler-cloud/prowler/pull/8200)
- `vm_jit_access_enabled` check for Azure provider [(#8202)](https://github.com/prowler-cloud/prowler/pull/8202)
- Bedrock AgentCore privilege escalation combination for AWS provider [(#8526)](https://github.com/prowler-cloud/prowler/pull/8526)
- Add User Email and APP name/installations information in GitHub provider [(#8501)](https://github.com/prowler-cloud/prowler/pull/8501)
- Remove standalone iam:PassRole from privesc detection and add missing patterns [(#8530)](https://github.com/prowler-cloud/prowler/pull/8530)
- Support session/profile/role/static credentials in Security Hub integration [(#8539)](https://github.com/prowler-cloud/prowler/pull/8539)
- `eks_cluster_deletion_protection_enabled` check for AWS provider [(#8536)](https://github.com/prowler-cloud/prowler/pull/8536)
- ECS privilege escalation patterns (StartTask and RunTask) for AWS provider [(#8541)](https://github.com/prowler-cloud/prowler/pull/8541)
- Resource Explorer enumeration v2 API actions in `cloudtrail_threat_detection_enumeration` check [(#8557)](https://github.com/prowler-cloud/prowler/pull/8557)
- `apim_threat_detection_llm_jacking` check for Azure provider [(#8571)](https://github.com/prowler-cloud/prowler/pull/8571)
- GCP `--skip-api-check` command line flag [(#8575)](https://github.com/prowler-cloud/prowler/pull/8575)

### Changed
- Refine kisa isms-p compliance mapping [(#8479)](https://github.com/prowler-cloud/prowler/pull/8479)
- Improve AWS Security Hub region check using multiple threads [(#8365)](https://github.com/prowler-cloud/prowler/pull/8365)

### Fixed
- Resource metadata error in `s3_bucket_shadow_resource_vulnerability` check [(#8572)](https://github.com/prowler-cloud/prowler/pull/8572)
- GitHub App authentication through API fails with auth_method validation error [(#8587)](https://github.com/prowler-cloud/prowler/pull/8587)
- AWS resource-arn filtering [(#8533)](https://github.com/prowler-cloud/prowler/pull/8533)
- GitHub App authentication for GitHub provider [(#8529)](https://github.com/prowler-cloud/prowler/pull/8529)
- List all accessible organizations in GitHub provider [(#8535)](https://github.com/prowler-cloud/prowler/pull/8535)
- Only evaluate enabled accounts in `entra_users_mfa_capable` check [(#8544)](https://github.com/prowler-cloud/prowler/pull/8544)
- GitHub Personal Access Token authentication fails without `user:email` scope [(#8580)](https://github.com/prowler-cloud/prowler/pull/8580)

---

## [5.10.2] (Prowler v5.10.2)

### Fixed
- Order requirements by ID in Prowler ThreatScore AWS compliance framework [(#8495)](https://github.com/prowler-cloud/prowler/pull/8495)
- Add explicit resource name to GCP and Azure Defender checks [(#8352)](https://github.com/prowler-cloud/prowler/pull/8352)
- Validation errors in Azure and M365 providers [(#8353)](https://github.com/prowler-cloud/prowler/pull/8353)
- Azure `app_http_logs_enabled` check false positives [(#8507)](https://github.com/prowler-cloud/prowler/pull/8507)
- Azure `storage_geo_redundant_enabled` check false positives [(#8504)](https://github.com/prowler-cloud/prowler/pull/8504)
- AWS `kafka_cluster_is_public` check false positives [(#8514)](https://github.com/prowler-cloud/prowler/pull/8514)
- List all accessible repositories in GitHub [(#8522)](https://github.com/prowler-cloud/prowler/pull/8522)
- GitHub CIS 1.0 Compliance Reports [(#8519)](https://github.com/prowler-cloud/prowler/pull/8519)

---

## [5.10.1] (Prowler v5.10.1)

### Fixed
- Remove invalid requirements from CIS 1.0 for GitHub provider [(#8472)](https://github.com/prowler-cloud/prowler/pull/8472)

---

## [5.10.0] (Prowler v5.10.0)

### Added
- `bedrock_api_key_no_administrative_privileges` check for AWS provider [(#8321)](https://github.com/prowler-cloud/prowler/pull/8321)
- `bedrock_api_key_no_long_term_credentials` check for AWS provider [(#8396)](https://github.com/prowler-cloud/prowler/pull/8396)
- Support App Key Content in GitHub provider [(#8271)](https://github.com/prowler-cloud/prowler/pull/8271)
- CIS 4.0 for the Azure provider [(#7782)](https://github.com/prowler-cloud/prowler/pull/7782)
- `vm_desired_sku_size` check for Azure provider [(#8191)](https://github.com/prowler-cloud/prowler/pull/8191)
- `vm_scaleset_not_empty` check for Azure provider [(#8192)](https://github.com/prowler-cloud/prowler/pull/8192)
- GitHub repository and organization scoping support with `--repository/respositories` and `--organization/organizations` flags [(#8329)](https://github.com/prowler-cloud/prowler/pull/8329)
- GCP provider retry configuration [(#8412)](https://github.com/prowler-cloud/prowler/pull/8412)
- `s3_bucket_shadow_resource_vulnerability` check for AWS provider [(#8398)](https://github.com/prowler-cloud/prowler/pull/8398)
- Use `trivy` as engine for IaC provider [(#8466)](https://github.com/prowler-cloud/prowler/pull/8466)

### Changed
- Handle some AWS errors as warnings instead of errors [(#8347)](https://github.com/prowler-cloud/prowler/pull/8347)
- Revert import of `checkov` python library [(#8385)](https://github.com/prowler-cloud/prowler/pull/8385)
- Updated policy mapping in ISMS-P compliance file for improved alignment [(#8367)](https://github.com/prowler-cloud/prowler/pull/8367)

### Fixed
- False positives in SQS encryption check for ephemeral queues [(#8330)](https://github.com/prowler-cloud/prowler/pull/8330)
- Add protocol validation check in security group checks to ensure proper protocol matching [(#8374)](https://github.com/prowler-cloud/prowler/pull/8374)
- Add missing audit evidence for controls 1.1.4 and 2.5.5 for ISMS-P compliance. [(#8386)](https://github.com/prowler-cloud/prowler/pull/8386)
- Use the correct @staticmethod decorator for `set_identity` and `set_session_config` methods in AwsProvider [(#8056)](https://github.com/prowler-cloud/prowler/pull/8056)
- Use the correct default value for `role_session_name` and `session_duration` in AwsSetUpSession [(#8056)](https://github.com/prowler-cloud/prowler/pull/8056)
- Use the correct default value for `role_session_name` and `session_duration` in S3 [(#8417)](https://github.com/prowler-cloud/prowler/pull/8417)
- GitHub App authentication fails to generate output files and HTML header sections [(#8423)](https://github.com/prowler-cloud/prowler/pull/8423)
- S3 `test_connection` uses AWS S3 API `HeadBucket` instead of `GetBucketLocation` [(#8456)](https://github.com/prowler-cloud/prowler/pull/8456)
- Add more validations to Azure Storage models when some values are None to avoid serialization issues [(#8325)](https://github.com/prowler-cloud/prowler/pull/8325)
- `sns_topics_not_publicly_accessible` false positive with `aws:SourceArn` conditions [(#8326)](https://github.com/prowler-cloud/prowler/issues/8326)
- Remove typo from description req 1.2.3 - Prowler ThreatScore m365 [(#8384)](https://github.com/prowler-cloud/prowler/pull/8384)
- Way of counting FAILED/PASS reqs from `kisa_isms_p_2023_aws` table [(#8382)](https://github.com/prowler-cloud/prowler/pull/8382)
- Use default tenant domain instead of first domain in list for Azure and M365 providers [(#8402)](https://github.com/prowler-cloud/prowler/pull/8402)
- Avoid multiple module error calls in M365 provider [(#8353)](https://github.com/prowler-cloud/prowler/pull/8353)
- Avoid sending errors to Sentry in M365 provider when user authentication fails [(#8420)](https://github.com/prowler-cloud/prowler/pull/8420)
- Tweaks from Prowler ThreatScore in order to handle the correct reqs [(#8401)](https://github.com/prowler-cloud/prowler/pull/8401)
- Make `setup_assumed_session` static for the AWS provider [(#8419)](https://github.com/prowler-cloud/prowler/pull/8419)

---

## [5.9.2] (Prowler v5.9.2)

### Fixed
- Use the correct resource name in `defender_domain_dkim_enabled` check [(#8334)](https://github.com/prowler-cloud/prowler/pull/8334)

---

## [5.9.0] (Prowler v5.9.0)

### Added
- `storage_smb_channel_encryption_with_secure_algorithm` check for Azure provider [(#8123)](https://github.com/prowler-cloud/prowler/pull/8123)
- `storage_smb_protocol_version_is_latest` check for Azure provider [(#8128)](https://github.com/prowler-cloud/prowler/pull/8128)
- `vm_backup_enabled` check for Azure provider [(#8182)](https://github.com/prowler-cloud/prowler/pull/8182)
- `vm_linux_enforce_ssh_authentication` check for Azure provider [(#8149)](https://github.com/prowler-cloud/prowler/pull/8149)
- `vm_ensure_using_approved_images` check for Azure provider [(#8168)](https://github.com/prowler-cloud/prowler/pull/8168)
- `vm_scaleset_associated_load_balancer` check for Azure provider [(#8181)](https://github.com/prowler-cloud/prowler/pull/8181)
- `defender_attack_path_notifications_properly_configured` check for Azure provider [(#8245)](https://github.com/prowler-cloud/prowler/pull/8245)
- `entra_intune_enrollment_sign_in_frequency_every_time` check for M365 provider [(#8223)](https://github.com/prowler-cloud/prowler/pull/8223)
- Support for remote repository scanning in IaC provider [(#8193)](https://github.com/prowler-cloud/prowler/pull/8193)
- Add `test_connection` method to GitHub provider [(#8248)](https://github.com/prowler-cloud/prowler/pull/8248)

### Changed
- Refactor the Azure Defender get security contact configuration method to use the API REST endpoint instead of the SDK [(#8241)](https://github.com/prowler-cloud/prowler/pull/8241)

### Fixed
- Title & description wording for `iam_user_accesskey_unused` check for AWS provider [(#8233)](https://github.com/prowler-cloud/prowler/pull/8233)
- Add GitHub provider to lateral panel in documentation and change -h environment variable output [(#8246)](https://github.com/prowler-cloud/prowler/pull/8246)
- Show `m365_identity_type` and `m365_identity_id` in cloud reports [(#8247)](https://github.com/prowler-cloud/prowler/pull/8247)
- Ensure `is_service_role` only returns `True` for service roles [(#8274)](https://github.com/prowler-cloud/prowler/pull/8274)
- Update DynamoDB check metadata to fix broken link [(#8273)](https://github.com/prowler-cloud/prowler/pull/8273)
- Show correct count of findings in Dashboard Security Posture page [(#8270)](https://github.com/prowler-cloud/prowler/pull/8270)
- Add Check's metadata service name validator [(#8289)](https://github.com/prowler-cloud/prowler/pull/8289)
- Use subscription ID in Azure mutelist [(#8290)](https://github.com/prowler-cloud/prowler/pull/8290)
- `ServiceName` field in Network Firewall checks metadata [(#8280)](https://github.com/prowler-cloud/prowler/pull/8280)
- Update `entra_users_mfa_capable` check to use the correct resource name and ID [(#8288)](https://github.com/prowler-cloud/prowler/pull/8288)
- Handle multiple services and severities while listing checks [(#8302)](https://github.com/prowler-cloud/prowler/pull/8302)
- Handle `tenant_id` for M365 Mutelist [(#8306)](https://github.com/prowler-cloud/prowler/pull/8306)
- Fix error in Dashboard Overview page when reading CSV files [(#8257)](https://github.com/prowler-cloud/prowler/pull/8257)

---

## [5.8.1] (Prowler v5.8.1)

### Fixed
- Detect wildcarded ARNs in sts:AssumeRole policy resources [(#8164)](https://github.com/prowler-cloud/prowler/pull/8164)
- List all streams and `firehose_stream_encrypted_at_rest` logic [(#8213)](https://github.com/prowler-cloud/prowler/pull/8213)
- Allow empty values for http_endpoint in templates [(#8184)](https://github.com/prowler-cloud/prowler/pull/8184)
- Convert all Azure Storage models to Pydantic models to avoid serialization issues [(#8222)](https://github.com/prowler-cloud/prowler/pull/8222)

---

## [5.8.0] (Prowler v5.8.0)

### Added

- `storage_geo_redundant_enabled` check for Azure provider [(#7980)](https://github.com/prowler-cloud/prowler/pull/7980)
- `storage_cross_tenant_replication_disabled` check for Azure provider [(#7977)](https://github.com/prowler-cloud/prowler/pull/7977)
- CIS 1.11 compliance framework for Kubernetes [(#7790)](https://github.com/prowler-cloud/prowler/pull/7790)
- Support `HTTPS_PROXY` and `K8S_SKIP_TLS_VERIFY` in Kubernetes [(#7720)](https://github.com/prowler-cloud/prowler/pull/7720)
- Weight for Prowler ThreatScore scoring [(#7795)](https://github.com/prowler-cloud/prowler/pull/7795)
- `entra_users_mfa_capable` check for M365 provider [(#7734)](https://github.com/prowler-cloud/prowler/pull/7734)
- `admincenter_organization_customer_lockbox_enabled` check for M365 provider [(#7732)](https://github.com/prowler-cloud/prowler/pull/7732)
- `admincenter_external_calendar_sharing_disabled` check for M365 provider [(#7733)](https://github.com/prowler-cloud/prowler/pull/7733)
- Level for Prowler ThreatScore in the accordion in Dashboard [(#7739)](https://github.com/prowler-cloud/prowler/pull/7739)
- CIS 4.0 compliance framework for GCP [(7785)](https://github.com/prowler-cloud/prowler/pull/7785)
- `repository_has_codeowners_file` check for GitHub provider [(#7752)](https://github.com/prowler-cloud/prowler/pull/7752)
- `repository_default_branch_requires_signed_commits` check for GitHub provider [(#7777)](https://github.com/prowler-cloud/prowler/pull/7777)
- `repository_inactive_not_archived` check for GitHub provider [(#7786)](https://github.com/prowler-cloud/prowler/pull/7786)
- `repository_dependency_scanning_enabled` check for GitHub provider [(#7771)](https://github.com/prowler-cloud/prowler/pull/7771)
- `repository_secret_scanning_enabled` check for GitHub provider [(#7759)](https://github.com/prowler-cloud/prowler/pull/7759)
- `repository_default_branch_requires_codeowners_review` check for GitHub provider [(#7753)](https://github.com/prowler-cloud/prowler/pull/7753)
- NIS 2 compliance framework for AWS [(#7839)](https://github.com/prowler-cloud/prowler/pull/7839)
- NIS 2 compliance framework for Azure [(#7857)](https://github.com/prowler-cloud/prowler/pull/7857)
- Search bar in Dashboard Overview page [(#7804)](https://github.com/prowler-cloud/prowler/pull/7804)
- NIS 2 compliance framework for GCP [(#7912)](https://github.com/prowler-cloud/prowler/pull/7912)
- `storage_account_key_access_disabled` check for Azure provider [(#7974)](https://github.com/prowler-cloud/prowler/pull/7974)
- `storage_ensure_file_shares_soft_delete_is_enabled` check for Azure provider [(#7966)](https://github.com/prowler-cloud/prowler/pull/7966)
- Make `validate_mutelist` method static inside `Mutelist` class [(#7811)](https://github.com/prowler-cloud/prowler/pull/7811)
- Avoid bypassing IAM check using wildcards [(#7708)](https://github.com/prowler-cloud/prowler/pull/7708)
- `storage_blob_versioning_is_enabled` new check for Azure provider [(#7927)](https://github.com/prowler-cloud/prowler/pull/7927)
- New method to authenticate in AppInsights in check `app_function_application_insights_enabled` [(#7763)](https://github.com/prowler-cloud/prowler/pull/7763)
- ISO 27001 2022 for M365 provider [(#7985)](https://github.com/prowler-cloud/prowler/pull/7985)
- `codebuild_project_uses_allowed_github_organizations` check for AWS provider [(#7595)](https://github.com/prowler-cloud/prowler/pull/7595)
- IaC provider [(#7852)](https://github.com/prowler-cloud/prowler/pull/7852)
- Azure Databricks service integration for Azure provider, including the `databricks_workspace_vnet_injection_enabled` check [(#8008)](https://github.com/prowler-cloud/prowler/pull/8008)
- `databricks_workspace_cmk_encryption_enabled` check for Azure provider [(#8017)](https://github.com/prowler-cloud/prowler/pull/8017)
- Appication auth for PowerShell in M365 provider [(#7992)](https://github.com/prowler-cloud/prowler/pull/7992)
- `storage_account_default_to_entra_authorization_enabled` check for Azure provider [(#7981)](https://github.com/prowler-cloud/prowler/pull/7981)
- Improve overview page from Prowler Dashboard [(#8118)](https://github.com/prowler-cloud/prowler/pull/8118)
- `keyvault_ensure_public_network_access_disabled` check for Azure provider [(#8072)](https://github.com/prowler-cloud/prowler/pull/8072)
- `monitor_alert_service_health_exists` check for Azure provider [(#8067)](https://github.com/prowler-cloud/prowler/pull/8067)
- Replace `Domain.Read.All` with `Directory.Read.All` in Azure and M365 docs [(#8075)](https://github.com/prowler-cloud/prowler/pull/8075)
- Refactor IaC provider to use Checkov as Python library [(#8093)](https://github.com/prowler-cloud/prowler/pull/8093)
- New check `codebuild_project_not_publicly_accessible` for AWS provider [(#8127)](https://github.com/prowler-cloud/prowler/pull/8127)

### Fixed
- Consolidate Azure Storage file service properties to the account level, improving the accuracy of the `storage_ensure_file_shares_soft_delete_is_enabled` check [(#8087)](https://github.com/prowler-cloud/prowler/pull/8087)
- Migrate Azure VM service and managed disk logic to Pydantic models for better serialization and type safety, and update all related tests to use the new models and fix UUID handling [(#https://github.com/prowler-cloud/prowler/pull/8151)](https://github.com/prowler-cloud/prowler/pull/https://github.com/prowler-cloud/prowler/pull/8151)
- `organizations_scp_check_deny_regions` check to pass when SCP policies have no statements [(#8091)](https://github.com/prowler-cloud/prowler/pull/8091)
- Fix logic in VPC and ELBv2 checks [(#8077)](https://github.com/prowler-cloud/prowler/pull/8077)
- Retrieve correctly ECS Container insights settings [(#8097)](https://github.com/prowler-cloud/prowler/pull/8097)
- Fix correct handling for different accounts-dates in prowler dashboard compliance page [(#8108)](https://github.com/prowler-cloud/prowler/pull/8108)
- Handling of `block-project-ssh-keys` in GCP check `compute_instance_block_project_wide_ssh_keys_disabled` [(#8115)](https://github.com/prowler-cloud/prowler/pull/8115)
- Handle empty name in Azure Defender and GCP checks [(#8120)](https://github.com/prowler-cloud/prowler/pull/8120)

### Changed
- Reworked `S3.test_connection` to match the AwsProvider logic [(#8088)](https://github.com/prowler-cloud/prowler/pull/8088)

### Removed
- OCSF version number references to point always to the latest [(#8064)](https://github.com/prowler-cloud/prowler/pull/8064)

---

## [5.7.5] (Prowler v5.7.5)

### Fixed
- Use unified timestamp for all requirements [(#8059)](https://github.com/prowler-cloud/prowler/pull/8059)
- Add EKS to service without subservices [(#7959)](https://github.com/prowler-cloud/prowler/pull/7959)
- `apiserver_strong_ciphers_only` check for K8S provider [(#7952)](https://github.com/prowler-cloud/prowler/pull/7952)
- Handle `0` at the start and end of account uids in Prowler Dashboard [(#7955)](https://github.com/prowler-cloud/prowler/pull/7955)
- Typo in PCI 4.0 for K8S provider [(#7971)](https://github.com/prowler-cloud/prowler/pull/7971)
- AWS root credentials checks always verify if root credentials are enabled [(#7967)](https://github.com/prowler-cloud/prowler/pull/7967)
- Github provider to `usage` section of `prowler -h`: [(#7906)](https://github.com/prowler-cloud/prowler/pull/7906)
- `network_flow_log_more_than_90_days` check to pass when retention policy is 0 days [(#7975)](https://github.com/prowler-cloud/prowler/pull/7975)
- Update SDK Azure call for ftps_state in the App Service [(#7923)](https://github.com/prowler-cloud/prowler/pull/7923)
- Validate ResourceType in CheckMetadata [(#8035)](https://github.com/prowler-cloud/prowler/pull/8035)
- Missing ResourceType values in check's metadata [(#8028)](https://github.com/prowler-cloud/prowler/pull/8028)
- Avoid user requests in setup_identity app context and user auth log enhancement [(#8043)](https://github.com/prowler-cloud/prowler/pull/8043)

---

## [5.7.3] (Prowler v5.7.3)

### Fixed
- Automatically encrypt password in Microsoft365 provider [(#7784)](https://github.com/prowler-cloud/prowler/pull/7784)
- Remove last encrypted password appearances [(#7825)](https://github.com/prowler-cloud/prowler/pull/7825)

---

## [5.7.2] (Prowler v5.7.2)

### Fixed
- `m365_powershell test_credentials` to use sanitized credentials [(#7761)](https://github.com/prowler-cloud/prowler/pull/7761)
- `admincenter_users_admins_reduced_license_footprint` check logic to pass when admin user has no license [(#7779)](https://github.com/prowler-cloud/prowler/pull/7779)
- `m365_powershell` to close the PowerShell sessions in msgraph services [(#7816)](https://github.com/prowler-cloud/prowler/pull/7816)
- `defender_ensure_notify_alerts_severity_is_high`check to accept high or lower severity [(#7862)](https://github.com/prowler-cloud/prowler/pull/7862)
- Replace `Directory.Read.All` permission with `Domain.Read.All` which is more restrictive [(#7888)](https://github.com/prowler-cloud/prowler/pull/7888)
- Split calls to list Azure Functions attributes [(#7778)](https://github.com/prowler-cloud/prowler/pull/7778)

---

## [5.7.0] (Prowler v5.7.0)

### Added
- Update the compliance list supported for each provider from docs [(#7694)](https://github.com/prowler-cloud/prowler/pull/7694)
- Allow setting cluster name in in-cluster mode in Kubernetes [(#7695)](https://github.com/prowler-cloud/prowler/pull/7695)
- Prowler ThreatScore for M365 provider [(#7692)](https://github.com/prowler-cloud/prowler/pull/7692)
- GitHub provider [(#5787)](https://github.com/prowler-cloud/prowler/pull/5787)
- `repository_default_branch_requires_multiple_approvals` check for GitHub provider [(#6160)](https://github.com/prowler-cloud/prowler/pull/6160)
- `repository_default_branch_protection_enabled` check for GitHub provider [(#6161)](https://github.com/prowler-cloud/prowler/pull/6161)
- `repository_default_branch_requires_linear_history` check for GitHub provider [(#6162)](https://github.com/prowler-cloud/prowler/pull/6162)
- `repository_default_branch_disallows_force_push` check for GitHub provider [(#6197)](https://github.com/prowler-cloud/prowler/pull/6197)
- `repository_default_branch_deletion_disabled` check for GitHub provider [(#6200)](https://github.com/prowler-cloud/prowler/pull/6200)
- `repository_default_branch_status_checks_required` check for GitHub provider [(#6204)](https://github.com/prowler-cloud/prowler/pull/6204)
- `repository_default_branch_protection_applies_to_admins` check for GitHub provider [(#6205)](https://github.com/prowler-cloud/prowler/pull/6205)
- `repository_branch_delete_on_merge_enabled` check for GitHub provider [(#6209)](https://github.com/prowler-cloud/prowler/pull/6209)
- `repository_default_branch_requires_conversation_resolution` check for GitHub provider [(#6208)](https://github.com/prowler-cloud/prowler/pull/6208)
- `organization_members_mfa_required` check for GitHub provider [(#6304)](https://github.com/prowler-cloud/prowler/pull/6304)
- GitHub provider documentation and CIS v1.0.0 compliance [(#6116)](https://github.com/prowler-cloud/prowler/pull/6116)
- CIS 5.0 compliance framework for AWS [(7766)](https://github.com/prowler-cloud/prowler/pull/7766)

### Fixed
- Update CIS 4.0 for M365 provider [(#7699)](https://github.com/prowler-cloud/prowler/pull/7699)
- Update and upgrade CIS for all the providers [(#7738)](https://github.com/prowler-cloud/prowler/pull/7738)
- Cover policies with conditions with SNS endpoint in `sns_topics_not_publicly_accessible` [(#7750)](https://github.com/prowler-cloud/prowler/pull/7750)
- Change severity logic for `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` check [(#7764)](https://github.com/prowler-cloud/prowler/pull/7764)

---

## [5.6.0] (Prowler v5.6.0)

### Added
- SOC2 compliance framework to Azure [(#7489)](https://github.com/prowler-cloud/prowler/pull/7489)
- Check for unused Service Accounts in GCP [(#7419)](https://github.com/prowler-cloud/prowler/pull/7419)
- Powershell to Microsoft365 [(#7331)](https://github.com/prowler-cloud/prowler/pull/7331)
- Service Defender to Microsoft365 with one check for Common Attachments filter enabled in Malware Policies [(#7425)](https://github.com/prowler-cloud/prowler/pull/7425)
- Check for Outbound Antispam Policy well configured in service Defender for M365 [(#7480)](https://github.com/prowler-cloud/prowler/pull/7480)
- Check for Antiphishing Policy well configured in service Defender in M365 [(#7453)](https://github.com/prowler-cloud/prowler/pull/7453)
- Check for Notifications for Internal users enabled in Malware Policies from service Defender in M365 [(#7435)](https://github.com/prowler-cloud/prowler/pull/7435)
- Support CLOUDSDK_AUTH_ACCESS_TOKEN in GCP [(#7495)](https://github.com/prowler-cloud/prowler/pull/7495)
- Service Exchange to Microsoft365 with one check for Organizations Mailbox Auditing enabled [(#7408)](https://github.com/prowler-cloud/prowler/pull/7408)
- Check for Bypass Disable in every Mailbox for service Defender in M365 [(#7418)](https://github.com/prowler-cloud/prowler/pull/7418)
- New check `teams_external_domains_restricted` [(#7557)](https://github.com/prowler-cloud/prowler/pull/7557)
- New check `teams_email_sending_to_channel_disabled` [(#7533)](https://github.com/prowler-cloud/prowler/pull/7533)
- New check for External Mails Tagged for service Exchange in M365 [(#7580)](https://github.com/prowler-cloud/prowler/pull/7580)
- New check for WhiteList not used in Transport Rules for service Defender in M365 [(#7569)](https://github.com/prowler-cloud/prowler/pull/7569)
- Check for Inbound Antispam Policy with no allowed domains from service Defender in M365 [(#7500)](https://github.com/prowler-cloud/prowler/pull/7500)
- New check `teams_meeting_anonymous_user_join_disabled` [(#7565)](https://github.com/prowler-cloud/prowler/pull/7565)
- New check `teams_unmanaged_communication_disabled` [(#7561)](https://github.com/prowler-cloud/prowler/pull/7561)
- New check `teams_external_users_cannot_start_conversations` [(#7562)](https://github.com/prowler-cloud/prowler/pull/7562)
- New check for AllowList not used in the Connection Filter Policy from service Defender in M365 [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- New check for SafeList not enabled in the Connection Filter Policy from service Defender in M365 [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- New check for DKIM enabled for service Defender in M365 [(#7485)](https://github.com/prowler-cloud/prowler/pull/7485)
- New check `teams_meeting_anonymous_user_start_disabled` [(#7567)](https://github.com/prowler-cloud/prowler/pull/7567)
- New check `teams_meeting_external_lobby_bypass_disabled` [(#7568)](https://github.com/prowler-cloud/prowler/pull/7568)
- New check `teams_meeting_dial_in_lobby_bypass_disabled` [(#7571)](https://github.com/prowler-cloud/prowler/pull/7571)
- New check `teams_meeting_external_control_disabled` [(#7604)](https://github.com/prowler-cloud/prowler/pull/7604)
- New check `teams_meeting_external_chat_disabled` [(#7605)](https://github.com/prowler-cloud/prowler/pull/7605)
- New check `teams_meeting_recording_disabled` [(#7607)](https://github.com/prowler-cloud/prowler/pull/7607)
- New check `teams_meeting_presenters_restricted` [(#7613)](https://github.com/prowler-cloud/prowler/pull/7613)
- New check `teams_security_reporting_enabled` [(#7614)](https://github.com/prowler-cloud/prowler/pull/7614)
- New check `defender_chat_report_policy_configured` [(#7614)](https://github.com/prowler-cloud/prowler/pull/7614)
- New check `teams_meeting_chat_anonymous_users_disabled` [(#7579)](https://github.com/prowler-cloud/prowler/pull/7579)
- Prowler Threat Score Compliance Framework [(#7603)](https://github.com/prowler-cloud/prowler/pull/7603)
- Documentation for M365 provider [(#7622)](https://github.com/prowler-cloud/prowler/pull/7622)
- Support for m365 provider in Prowler Dashboard [(#7633)](https://github.com/prowler-cloud/prowler/pull/7633)
- New check for Modern Authentication enabled for Exchange Online in M365 [(#7636)](https://github.com/prowler-cloud/prowler/pull/7636)
- New check `sharepoint_onedrive_sync_restricted_unmanaged_devices` [(#7589)](https://github.com/prowler-cloud/prowler/pull/7589)
- New check for Additional Storage restricted for Exchange in M365 [(#7638)](https://github.com/prowler-cloud/prowler/pull/7638)
- New check for Roles Assignment Policy with no AddIns for Exchange in M365 [(#7644)](https://github.com/prowler-cloud/prowler/pull/7644)
- New check for Auditing Mailbox on E3 users is enabled for Exchange in M365 [(#7642)](https://github.com/prowler-cloud/prowler/pull/7642)
- New check for SMTP Auth disabled for Exchange in M365 [(#7640)](https://github.com/prowler-cloud/prowler/pull/7640)
- New check for MailTips full enabled for Exchange in M365 [(#7637)](https://github.com/prowler-cloud/prowler/pull/7637)
- New check for Comprehensive Attachments Filter Applied for Defender in M365 [(#7661)](https://github.com/prowler-cloud/prowler/pull/7661)
- Modified check `exchange_mailbox_properties_auditing_enabled` to make it configurable [(#7662)](https://github.com/prowler-cloud/prowler/pull/7662)
- snapshots to m365 documentation [(#7673)](https://github.com/prowler-cloud/prowler/pull/7673)
- support for static credentials for sending findings to Amazon S3 and AWS Security Hub [(#7322)](https://github.com/prowler-cloud/prowler/pull/7322)
- Prowler ThreatScore for M365 provider [(#7692)](https://github.com/prowler-cloud/prowler/pull/7692)
- Microsoft User and User Credential auth to reports [(#7681)](https://github.com/prowler-cloud/prowler/pull/7681)

### Fixed
- Package name location in pyproject.toml while replicating for prowler-cloud [(#7531)](https://github.com/prowler-cloud/prowler/pull/7531)
- Remove cache in PyPI release action [(#7532)](https://github.com/prowler-cloud/prowler/pull/7532)
- The correct values for logger.info inside iam service [(#7526)](https://github.com/prowler-cloud/prowler/pull/7526)
- Update S3 bucket naming validation to accept dots [(#7545)](https://github.com/prowler-cloud/prowler/pull/7545)
- Handle new FlowLog model properties in Azure [(#7546)](https://github.com/prowler-cloud/prowler/pull/7546)
- Improve compliance and dashboard [(#7596)](https://github.com/prowler-cloud/prowler/pull/7596)
- Remove invalid parameter `create_file_descriptor` [(#7600)](https://github.com/prowler-cloud/prowler/pull/7600)
- Remove first empty line in HTML output [(#7606)](https://github.com/prowler-cloud/prowler/pull/7606)
- Remove empty files in Prowler [(#7627)](https://github.com/prowler-cloud/prowler/pull/7627)
- Ensure that ContentType in upload_file matches the uploaded file's format [(#7635)](https://github.com/prowler-cloud/prowler/pull/7635)
- Incorrect check inside 4.4.1 requirement for Azure CIS 2.0 [(#7656)](https://github.com/prowler-cloud/prowler/pull/7656)
- Remove muted findings on compliance page from Prowler Dashboard [(#7683)](https://github.com/prowler-cloud/prowler/pull/7683)
- Remove duplicated findings on compliance page from Prowler Dashboard [(#7686)](https://github.com/prowler-cloud/prowler/pull/7686)
- Incorrect values for Prowler Threatscore compliance LevelOfRisk inside requirements [(#7667)](https://github.com/prowler-cloud/prowler/pull/7667)

---

## [5.5.1] (Prowler v5.5.1)

### Fixed
- Default name to contacts in Azure Defender [(#7483)](https://github.com/prowler-cloud/prowler/pull/7483)
- Handle projects without ID in GCP [(#7496)](https://github.com/prowler-cloud/prowler/pull/7496)
- Restore packages location in PyProject [(#7510)](https://github.com/prowler-cloud/prowler/pull/7510)

---
