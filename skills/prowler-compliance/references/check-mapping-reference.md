# Audit Reference: Requirement Text → Prowler Checks

Built from a real audit of 172 CCC ARs × 3 providers (April 2026). Use it to map
CCC-style / NIST-style / ISO-style requirement text to the checks that actually
verify them. Always re-validate every check id against the current inventory
(`assets/build_inventory.py` + `assets/query_checks.py`) before using a row —
checks get renamed and added over time.

**Entries containing `*` are glob patterns, NOT literal check ids** (e.g.
`iam_*_no_administrative_privileges`, `cloudwatch_log_metric_filter_*`,
`*_minimum_tls_version_12`). Copied verbatim into a compliance JSON they map
nothing — expand each pattern to the concrete check ids via
`python skills/prowler-compliance/assets/query_checks.py <provider> <keywords>`
before writing any mapping.

| Requirement text | AWS checks | Azure checks | GCP checks |
|---|---|---|---|
| **TLS in transit enforced** | `cloudfront_distributions_https_enabled`, `s3_bucket_secure_transport_policy`, `elbv2_ssl_listeners`, `elbv2_insecure_ssl_ciphers`, `elb_ssl_listeners`, `elb_insecure_ssl_ciphers`, `opensearch_service_domains_https_communications_enforced`, `rds_instance_transport_encrypted`, `redshift_cluster_in_transit_encryption_enabled`, `elasticache_redis_cluster_in_transit_encryption_enabled`, `dynamodb_accelerator_cluster_in_transit_encryption_enabled`, `dms_endpoint_ssl_enabled`, `kafka_cluster_in_transit_encryption_enabled`, `transfer_server_in_transit_encryption_enabled`, `glue_database_connections_ssl_enabled`, `sns_subscription_not_using_http_endpoints` | `storage_secure_transfer_required_is_enabled`, `storage_ensure_minimum_tls_version_12`, `postgresql_flexible_server_enforce_ssl_enabled`, `mysql_flexible_server_ssl_connection_enabled`, `mysql_flexible_server_minimum_tls_version_12`, `sqlserver_recommended_minimal_tls_version`, `app_minimum_tls_version_12`, `app_ensure_http_is_redirected_to_https`, `app_ftp_deployment_disabled` | `cloudsql_instance_ssl_connections` (almost only option) |
| **TLS 1.3 specifically** | Partial: `cloudfront_distributions_using_deprecated_ssl_protocols`, `elb*_insecure_ssl_ciphers`, `*_minimum_tls_version_12` | Partial: `*_minimum_tls_version_12` checks | None — accept as MANUAL |
| **SSH / port 22 hardening** | `ec2_instance_port_ssh_exposed_to_internet`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_22` | `network_ssh_internet_access_restricted`, `vm_linux_enforce_ssh_authentication` | `compute_firewall_ssh_access_from_the_internet_allowed`, `compute_instance_block_project_wide_ssh_keys_disabled`, `compute_project_os_login_enabled`, `compute_project_os_login_2fa_enabled` |
| **mTLS (mutual TLS)** | `kafka_cluster_mutual_tls_authentication_enabled`, `apigateway_restapi_client_certificate_enabled` | `app_client_certificates_on` | None — MANUAL |
| **Data at rest encrypted** | `s3_bucket_default_encryption`, `s3_bucket_kms_encryption`, `ec2_ebs_default_encryption`, `ec2_ebs_volume_encryption`, `rds_instance_storage_encrypted`, `rds_cluster_storage_encrypted`, `rds_snapshots_encrypted`, `dynamodb_tables_kms_cmk_encryption_enabled`, `redshift_cluster_encrypted_at_rest`, `neptune_cluster_storage_encrypted`, `documentdb_cluster_storage_encrypted`, `opensearch_service_domains_encryption_at_rest_enabled`, `kinesis_stream_encrypted_at_rest`, `firehose_stream_encrypted_at_rest`, `sns_topics_kms_encryption_at_rest_enabled`, `sqs_queues_server_side_encryption_enabled`, `efs_encryption_at_rest_enabled`, `athena_workgroup_encryption`, `glue_data_catalogs_metadata_encryption_enabled`, `backup_vaults_encrypted`, `backup_recovery_point_encrypted`, `cloudtrail_kms_encryption_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `eks_cluster_kms_cmk_encryption_in_secrets_enabled`, `sagemaker_notebook_instance_encryption_enabled`, `apigateway_restapi_cache_encrypted`, `kafka_cluster_encryption_at_rest_uses_cmk`, `dynamodb_accelerator_cluster_encryption_enabled`, `storagegateway_fileshare_encryption_enabled` | `storage_infrastructure_encryption_is_enabled`, `storage_ensure_encryption_with_customer_managed_keys`, `vm_ensure_attached_disks_encrypted_with_cmk`, `vm_ensure_unattached_disks_encrypted_with_cmk`, `sqlserver_tde_encryption_enabled`, `sqlserver_tde_encrypted_with_cmk`, `databricks_workspace_cmk_encryption_enabled`, `monitor_storage_account_with_activity_logs_cmk_encrypted` | `compute_instance_encryption_with_csek_enabled`, `dataproc_encrypted_with_cmks_disabled`, `bigquery_dataset_cmk_encryption`, `bigquery_table_cmk_encryption` |
| **CMEK required (customer-managed keys)** | `kms_cmk_are_used` | `storage_ensure_encryption_with_customer_managed_keys`, `vm_ensure_attached_disks_encrypted_with_cmk`, `vm_ensure_unattached_disks_encrypted_with_cmk`, `sqlserver_tde_encrypted_with_cmk`, `databricks_workspace_cmk_encryption_enabled` | `bigquery_dataset_cmk_encryption`, `bigquery_table_cmk_encryption`, `dataproc_encrypted_with_cmks_disabled`, `compute_instance_encryption_with_csek_enabled` |
| **Key rotation enabled** | `kms_cmk_rotation_enabled` | `keyvault_key_rotation_enabled`, `storage_key_rotation_90_days` | `kms_key_rotation_enabled` |
| **MFA for UI access** | `iam_root_mfa_enabled`, `iam_root_hardware_mfa_enabled`, `iam_user_mfa_enabled_console_access`, `iam_user_hardware_mfa_enabled`, `iam_administrator_access_with_mfa`, `cognito_user_pool_mfa_enabled` | `entra_privileged_user_has_mfa`, `entra_non_privileged_user_has_mfa`, `entra_user_with_vm_access_has_mfa`, `entra_security_defaults_enabled` | `compute_project_os_login_2fa_enabled` |
| **API access / credentials** | `iam_no_root_access_key`, `iam_user_no_setup_initial_access_key`, `apigateway_restapi_authorizers_enabled`, `apigateway_restapi_public_with_authorizer`, `apigatewayv2_api_authorizers_enabled` | `entra_conditional_access_policy_require_mfa_for_management_api`, `app_function_access_keys_configured`, `app_function_identity_is_configured` | `apikeys_api_restrictions_configured`, `apikeys_key_exists`, `apikeys_key_rotated_in_90_days` |
| **Log all admin/config changes** | `cloudtrail_multi_region_enabled`, `cloudtrail_multi_region_enabled_logging_management_events`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_log_file_validation_enabled`, `cloudwatch_log_metric_filter_*`, `cloudwatch_changes_to_*_alarm_configured`, `config_recorder_all_regions_enabled` | `monitor_diagnostic_settings_exists`, `monitor_diagnostic_setting_with_appropriate_categories`, `monitor_alert_*` | `iam_audit_logs_enabled`, `logging_log_metric_filter_and_alert_for_*`, `logging_sink_created` |
| **Log integrity (digital signatures)** | `cloudtrail_log_file_validation_enabled` (exact) | None | None |
| **Public access denied** | `s3_bucket_public_access`, `s3_bucket_public_list_acl`, `s3_bucket_public_write_acl`, `s3_account_level_public_access_blocks`, `apigateway_restapi_public`, `awslambda_function_url_public`, `awslambda_function_not_publicly_accessible`, `rds_instance_no_public_access`, `rds_snapshots_public_access`, `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`, `sns_topics_not_publicly_accessible`, `sqs_queues_not_publicly_accessible` | `storage_blob_public_access_level_is_disabled`, `storage_ensure_private_endpoints_in_storage_accounts`, `containerregistry_not_publicly_accessible`, `keyvault_private_endpoints`, `app_function_not_publicly_accessible`, `aks_clusters_public_access_disabled`, `network_http_internet_access_restricted` | `cloudstorage_bucket_public_access`, `compute_instance_public_ip`, `cloudsql_instance_public_ip`, `compute_firewall_*_access_from_the_internet_allowed` |
| **IAM least privilege** | `iam_*_no_administrative_privileges`, `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation`, `iam_role_administratoraccess_policy`, `iam_group_administrator_access_policy`, `iam_user_administrator_access_policy`, `iam_policy_attached_only_to_group_or_roles`, `iam_role_cross_service_confused_deputy_prevention` | `iam_role_user_access_admin_restricted`, `iam_subscription_roles_owner_custom_not_created`, `iam_custom_role_has_permissions_to_administer_resource_locks` | `iam_sa_no_administrative_privileges`, `iam_no_service_roles_at_project_level`, `iam_role_kms_enforce_separation_of_duties`, `iam_role_sa_enforce_separation_of_duties` |
| **Password policy** | `iam_password_policy_minimum_length_14`, `iam_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_symbol`, `iam_password_policy_number`, `iam_password_policy_expires_passwords_within_90_days_or_less`, `iam_password_policy_reuse_24` | None | None |
| **Credential rotation / unused** | `iam_rotate_access_key_90_days`, `iam_user_accesskey_unused`, `iam_user_console_access_unused` | None | `iam_sa_user_managed_key_rotate_90_days`, `iam_sa_user_managed_key_unused`, `iam_service_account_unused` |
| **VPC / flow logs** | `vpc_flow_logs_enabled` | `network_flow_log_captured_sent`, `network_watcher_enabled`, `network_flow_log_more_than_90_days` | `compute_subnet_flow_logs_enabled` |
| **Backup / DR / Multi-AZ** | `backup_vaults_exist`, `backup_plans_exist`, `backup_reportplans_exist`, `rds_instance_backup_enabled`, `rds_*_protected_by_backup_plan`, `rds_cluster_multi_az`, `neptune_cluster_backup_enabled`, `documentdb_cluster_backup_enabled`, `efs_have_backup_enabled`, `s3_bucket_cross_region_replication`, `dynamodb_table_protected_by_backup_plan` | `vm_backup_enabled`, `vm_sufficient_daily_backup_retention_period`, `storage_geo_redundant_enabled` | `cloudsql_instance_automated_backups`, `cloudstorage_bucket_log_retention_policy_lock`, `cloudstorage_bucket_sufficient_retention_period` |
| **Access analysis / discovery** | `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings` | None specific | `iam_account_access_approval_enabled`, `iam_cloud_asset_inventory_enabled` |
| **Object lock / retention** | `s3_bucket_object_lock`, `s3_bucket_object_versioning`, `s3_bucket_lifecycle_enabled`, `cloudtrail_bucket_requires_mfa_delete`, `s3_bucket_no_mfa_delete` | `storage_ensure_soft_delete_is_enabled`, `storage_blob_versioning_is_enabled`, `storage_ensure_file_shares_soft_delete_is_enabled` | `cloudstorage_bucket_log_retention_policy_lock`, `cloudstorage_bucket_soft_delete_enabled`, `cloudstorage_bucket_versioning_enabled`, `cloudstorage_bucket_sufficient_retention_period` |
| **Uniform bucket-level access** | `s3_bucket_acl_prohibited` | `storage_account_key_access_disabled`, `storage_default_to_entra_authorization_enabled` | `cloudstorage_bucket_uniform_bucket_level_access` |
| **Container vulnerability scanning** | `ecr_registry_scan_images_on_push_enabled`, `ecr_repositories_scan_vulnerabilities_in_latest_image` | `defender_container_images_scan_enabled`, `defender_container_images_resolved_vulnerabilities` | `artifacts_container_analysis_enabled`, `gcr_container_scanning_enabled` |
| **WAF / rate limiting** | `wafv2_webacl_with_rules`, `waf_*_webacl_with_rules`, `wafv2_webacl_logging_enabled`, `waf_global_webacl_logging_enabled` | None | None |
| **Deployment region restriction** | `organizations_scp_check_deny_regions` | None | None |
| **Secrets automatic rotation** | `secretsmanager_automatic_rotation_enabled`, `secretsmanager_secret_rotated_periodically` | `keyvault_rbac_secret_expiration_set`, `keyvault_non_rbac_secret_expiration_set` | None |
| **Certificate management** | `acm_certificates_expiration_check`, `acm_certificates_with_secure_key_algorithms`, `acm_certificates_transparency_logs_enabled` | `keyvault_key_expiration_set_in_non_rbac`, `keyvault_rbac_key_expiration_set`, `keyvault_non_rbac_secret_expiration_set` | None |
| **GenAI guardrails / input/output filtering** | `bedrock_guardrail_prompt_attack_filter_enabled`, `bedrock_guardrail_sensitive_information_filter_enabled`, `bedrock_agent_guardrail_enabled`, `bedrock_model_invocation_logging_enabled`, `bedrock_api_key_no_administrative_privileges`, `bedrock_api_key_no_long_term_credentials` | None | None |
| **ML dev environment security** | `sagemaker_notebook_instance_root_access_disabled`, `sagemaker_notebook_instance_without_direct_internet_access_configured`, `sagemaker_notebook_instance_vpc_settings_configured`, `sagemaker_models_vpc_settings_configured`, `sagemaker_training_jobs_vpc_settings_configured`, `sagemaker_training_jobs_network_isolation_enabled`, `sagemaker_training_jobs_volume_and_output_encryption_enabled` | None | None |
| **Threat detection / anomalous behavior** | `cloudtrail_threat_detection_enumeration`, `cloudtrail_threat_detection_privilege_escalation`, `cloudtrail_threat_detection_llm_jacking`, `guardduty_is_enabled`, `guardduty_no_high_severity_findings` | None | None |
| **Serverless private access** | `awslambda_function_inside_vpc`, `awslambda_function_not_publicly_accessible`, `awslambda_function_url_public` | `app_function_not_publicly_accessible` | None |

## What Prowler Does NOT Cover (accept MANUAL honestly)

Don't pad mappings for these — mark the requirement's checks empty and move on:

- **TLS 1.3 version specifically** — Prowler verifies TLS is enforced, not always the exact version
- **IANA port-protocol consistency** — no check for "protocol running on its assigned port"
- **mTLS on most Azure/GCP services** — limited to App Service client certs on Azure, nothing on GCP
- **Rate limiting** on monitoring endpoints, load balancers, serverless invocations, vector ingestion
- **Session cookie expiry** (LB stickiness)
- **HTTP header scrubbing** (Server, X-Powered-By)
- **Certificate transparency verification for imports**
- **Model version pinning, red teaming, AI quality review**
- **Vector embedding validation, dimensional constraints, ANN vs exact search**
- **Secret region replication** (cross-region residency)
- **Lifecycle cleanup policies on container registries**
- **Row-level / column-level security in data warehouses**
- **Deployment region restriction on Azure/GCP** (AWS has `organizations_scp_check_deny_regions`, others don't)
- **Cross-tenant alert silencing permissions**
- **Field-level masking in logs**
- **Managed view enforcement for database access**
- **Automatic MFA delete on all S3 buckets** (only CloudTrail bucket variant exists for some frameworks — AWS has the generic `s3_bucket_no_mfa_delete` though)

## Provider coverage asymmetry

AWS has dense coverage (in-transit encryption, IAM, database encryption, backup,
GenAI). Azure and GCP are thinner, especially for in-transit encryption, mTLS,
and ML/AI. Accept the asymmetry in mappings — don't force GCP parity where
Prowler genuinely can't verify. Newer providers (alibabacloud, oraclecloud,
googleworkspace, okta, cloudflare, linode...) have far smaller inventories:
always rebuild the inventory with `assets/build_inventory.py` before assuming
a mapping exists.
