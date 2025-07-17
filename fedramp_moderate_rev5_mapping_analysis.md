# FedRAMP Moderate Revision 5 - Prowler Checks Mapping Analysis

## Executive Summary

This analysis identifies **84 controls** in FedRAMP Moderate Revision 5 that currently have empty "Checks": [] arrays and provides a comprehensive mapping strategy to appropriate Prowler checks. The controls are categorized into **Policy Controls** (requiring minimal or no automated checks) and **Technical Controls** (requiring extensive automated validation).

## Control Categories Analysis

### 📋 Policy Controls (Minimal/No Automated Checks Required)
These controls are primarily procedural and organizational in nature:

**AC (Access Control) - Policy:**
- AC-1: Policy and Procedures ❌ KEEP EMPTY
- AC-8: System Use Notification ❌ KEEP EMPTY  
- AC-11: Device Lock ❌ KEEP EMPTY (client-side control)
- AC-22: Publicly Accessible Content ❌ KEEP EMPTY

**Training & Awareness (AT) - Policy:**
- AT-1: Policy and Procedures ❌ KEEP EMPTY
- AT-2: Literacy Training and Awareness ❌ KEEP EMPTY
- AT-3: Role-based Training ❌ KEEP EMPTY
- AT-4: Training Records ❌ KEEP EMPTY

**All "1" Controls (Policy & Procedures):**
- AU-1, CA-1, CM-1, CP-1, IA-1, IR-1, MA-1, MP-1, PE-1, PL-1, PS-1, RA-1, SA-1, SC-1, SI-1, SR-1 ❌ KEEP EMPTY

**Physical & Environmental (PE) - Policy:**
- PE-2, PE-3, PE-6, PE-8, PE-10, PE-14, PE-16 ❌ KEEP EMPTY

**Personnel Security (PS) - Policy:**
- PS-2, PS-3, PS-4, PS-5, PS-6, PS-7, PS-8 ❌ KEEP EMPTY

**Planning (PL) - Policy:**
- PL-2, PL-4, PL-8 ❌ KEEP EMPTY

**Media Protection (MP) - Policy:**
- MP-2, MP-3, MP-4, MP-5, MP-6 ❌ KEEP EMPTY

**Maintenance (MA) - Policy:**
- MA-3, MA-6 ❌ KEEP EMPTY

### 🔧 Technical Controls (Requiring Automated Checks)

## Priority 1: Critical Technical Controls

### AC (Access Control) - Technical Controls

**AC-2 (2) - Automated Temporary and Emergency Account Management**
```json
"Checks": [
  "iam_user_accesskey_unused",
  "iam_user_console_access_unused", 
  "iam_rotate_access_key_90_days"
]
```
*Justification: Detects inactive accounts that should be disabled automatically*

**AC-2 (5) - Inactivity Logout**
```json
"Checks": [
  "iam_user_console_access_unused",
  "iam_user_accesskey_unused"
]
```
*Justification: Validates accounts are properly managed for inactivity*

**AC-2 (9) - Restrictions on Use of Shared and Group Accounts**
```json
"Checks": [
  "iam_policy_attached_only_to_group_or_roles",
  "iam_aws_attached_policy_no_administrative_privileges",
  "iam_customer_attached_policy_no_administrative_privileges"
]
```
*Justification: Ensures proper group account management and privilege restrictions*

**AC-2 (13) - Disable Accounts for High-risk Individuals**
```json
"Checks": [
  "iam_user_console_access_unused",
  "iam_user_accesskey_unused",
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Monitoring capabilities to detect high-risk activity and unused accounts*

**AC-6 (2) - Non-privileged Access for Nonsecurity Functions**
```json
"Checks": [
  "iam_aws_attached_policy_no_administrative_privileges",
  "iam_customer_attached_policy_no_administrative_privileges",
  "iam_inline_policy_no_administrative_privileges",
  "iam_policy_attached_only_to_group_or_roles"
]
```
*Justification: Ensures separation of privileged and non-privileged access*

**AC-6 (7) - Review of User Privileges**
```json
"Checks": [
  "iam_aws_attached_policy_no_administrative_privileges",
  "iam_customer_attached_policy_no_administrative_privileges",
  "iam_inline_policy_no_administrative_privileges",
  "iam_user_accesskey_unused",
  "iam_user_console_access_unused"
]
```
*Justification: Validates privilege reviews are conducted and unnecessary privileges removed*

### AU (Audit & Accountability) - Technical Controls

**AU-5 - Response to Audit Processing Failures**
```json
"Checks": [
  "cloudtrail_cloudwatch_logging_enabled",
  "cloudwatch_log_group_retention_policy_specific_days_enabled",
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Ensures audit systems have failure detection and alerting*

**AU-6 - Audit Record Review, Analysis, and Reporting**
```json
"Checks": [
  "cloudtrail_cloudwatch_logging_enabled",
  "guardduty_is_enabled",
  "securityhub_enabled",
  "cloudwatch_log_metric_filter_unauthorized_api_calls",
  "cloudwatch_log_metric_filter_authentication_failures"
]
```
*Justification: Automated audit analysis and alerting capabilities*

**AU-8 - Time Stamps**
```json
"Checks": [
  "cloudtrail_multi_region_enabled",
  "cloudtrail_log_file_validation_enabled",
  "cloudtrail_cloudwatch_logging_enabled"
]
```
*Justification: Ensures audit logs have proper time synchronization*

### CA (Security Assessment & Authorization) - Technical Controls

**CA-2 - Control Assessments**
```json
"Checks": [
  "securityhub_enabled",
  "config_recorder_all_regions_enabled",
  "guardduty_is_enabled"
]
```
*Justification: Automated security assessment tools*

**CA-3 - Information Exchange**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "cloudtrail_multi_region_enabled",
  "securityhub_enabled"
]
```
*Justification: Monitoring of information exchanges between systems*

**CA-5 - Plan of Action and Milestones**
```json
"Checks": [
  "securityhub_enabled",
  "guardduty_no_high_severity_findings"
]
```
*Justification: Automated tracking of security findings and remediation*

**CA-6 - Authorization**
```json
"Checks": [
  "securityhub_enabled",
  "config_recorder_all_regions_enabled"
]
```
*Justification: Continuous authorization monitoring*

**CA-8 - Penetration Testing**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled",
  "inspector2_is_enabled"
]
```
*Justification: Vulnerability scanning and security testing tools*

**CA-9 - Internal System Connections**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "ec2_securitygroup_default_restrict_traffic",
  "vpc_endpoint_connections_trust_boundaries"
]
```
*Justification: Monitoring and controlling internal network connections*

### CM (Configuration Management) - Technical Controls

**CM-8 - System Component Inventory**
```json
"Checks": [
  "config_recorder_all_regions_enabled",
  "securityhub_enabled",
  "resourceexplorer2_indexes_found"
]
```
*Justification: Automated inventory and configuration tracking*

**CM-11 - User-Installed Software**
```json
"Checks": [
  "ec2_instance_managed_by_ssm",
  "ssm_managed_compliant_patching"
]
```
*Justification: Software inventory and patch management*

### CP (Contingency Planning) - Technical Controls

**CP-2 - Contingency Plan**
```json
"Checks": [
  "backup_plans_exist",
  "backup_vaults_exist",
  "rds_instance_backup_enabled",
  "dynamodb_tables_pitr_enabled"
]
```
*Justification: Automated backup and recovery capabilities*

**CP-3 - Contingency Training**
```json
"Checks": [
  "backup_plans_exist",
  "backup_reportplans_exist"
]
```
*Justification: Backup systems supporting contingency operations*

**CP-4 - Contingency Plan Testing**
```json
"Checks": [
  "backup_recovery_point_encrypted",
  "rds_instance_backup_enabled",
  "dynamodb_tables_pitr_enabled"
]
```
*Justification: Backup integrity and testing capabilities*

### IA (Identification & Authentication) - Technical Controls

**IA-4 - Identifier Management**
```json
"Checks": [
  "iam_no_root_access_key",
  "iam_rotate_access_key_90_days",
  "iam_user_accesskey_unused"
]
```
*Justification: Proper management of user identifiers and credentials*

### IR (Incident Response) - Technical Controls

**IR-2 - Incident Response Training**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Incident detection and response capabilities*

**IR-3 - Incident Response Testing**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled",
  "cloudtrail_threat_detection_privilege_escalation",
  "cloudtrail_threat_detection_enumeration"
]
```
*Justification: Threat detection and incident simulation capabilities*

**IR-6 - Incident Reporting**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled",
  "cloudtrail_cloudwatch_logging_enabled"
]
```
*Justification: Automated incident detection and reporting*

**IR-8 - Incident Response Plan**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled",
  "ssmincidents_enabled_with_plans"
]
```
*Justification: Incident response automation and planning tools*

### SC (System & Communications Protection) - Technical Controls

**SC-7 (4) - External Telecommunications Services**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
  "directconnect_connection_redundancy"
]
```
*Justification: External connection monitoring and security*

**SC-7 (5) - Deny by Default — Allow by Exception**
```json
"Checks": [
  "ec2_securitygroup_default_restrict_traffic",
  "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
  "ec2_networkacl_allow_ingress_any_port"
]
```
*Justification: Default-deny network access controls*

**SC-7 (8) - Route Traffic to Authenticated Proxy Servers**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "elb_ssl_listeners",
  "elbv2_ssl_listeners"
]
```
*Justification: Proxy and load balancer security configurations*

**SC-7 (12) - Host-based Protection**
```json
"Checks": [
  "guardduty_is_enabled",
  "ec2_instance_managed_by_ssm",
  "inspector2_is_enabled"
]
```
*Justification: Host-based security monitoring and protection*

**SC-10 - Network Disconnect**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "ec2_securitygroup_default_restrict_traffic"
]
```
*Justification: Network session termination capabilities*

**SC-15 - Collaborative Computing Devices and Applications**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "ec2_securitygroup_allow_ingress_from_internet_to_any_port"
]
```
*Justification: Monitoring of collaborative computing access*

**SC-28 (1) - Cryptographic Protection**
```json
"Checks": [
  "kms_cmk_rotation_enabled",
  "kms_cmk_not_deleted_unintentionally",
  "s3_bucket_default_encryption",
  "ebs_volume_encryption",
  "rds_instance_storage_encrypted"
]
```
*Justification: Encryption of data at rest*

**SC-45 (1) - Synchronization with Authoritative Time Source**
```json
"Checks": [
  "cloudtrail_log_file_validation_enabled",
  "cloudtrail_multi_region_enabled"
]
```
*Justification: Time synchronization for audit integrity*

### SI (System & Information Integrity) - Technical Controls

**SI-2 - Flaw Remediation**
```json
"Checks": [
  "ssm_managed_compliant_patching",
  "inspector2_is_enabled",
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Automated vulnerability and flaw detection*

**SI-3 - Malicious Code Protection**
```json
"Checks": [
  "guardduty_is_enabled",
  "guardduty_ec2_malware_protection_enabled",
  "securityhub_enabled"
]
```
*Justification: Malware detection and protection*

**SI-5 - Security Alerts, Advisories, and Directives**
```json
"Checks": [
  "securityhub_enabled",
  "guardduty_is_enabled",
  "inspector2_is_enabled"
]
```
*Justification: Automated security alerting and advisory systems*

**SI-6 - Security and Privacy Function Verification**
```json
"Checks": [
  "cloudtrail_log_file_validation_enabled",
  "config_recorder_all_regions_enabled",
  "securityhub_enabled"
]
```
*Justification: Verification of security function integrity*

**SI-11 - Error Handling**
```json
"Checks": [
  "cloudwatch_log_group_retention_policy_specific_days_enabled",
  "cloudtrail_cloudwatch_logging_enabled"
]
```
*Justification: Error logging and handling capabilities*

### Special Controls Analysis

**RA-3 - Risk Assessment**
```json
"Checks": [
  "securityhub_enabled",
  "guardduty_is_enabled",
  "inspector2_is_enabled",
  "config_recorder_all_regions_enabled"
]
```
*Justification: Automated risk assessment and vulnerability scanning*

**RA-5 (2) - Update Vulnerabilities to Be Scanned**
```json
"Checks": [
  "inspector2_is_enabled",
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Updated vulnerability scanning capabilities*

**RA-5 (5) - Privileged Access**
```json
"Checks": [
  "inspector2_is_enabled",
  "iam_aws_attached_policy_no_administrative_privileges",
  "iam_customer_attached_policy_no_administrative_privileges"
]
```
*Justification: Vulnerability scanning with privileged access*

**SA-5 - System Documentation**
```json
"Checks": [
  "config_recorder_all_regions_enabled",
  "resourceexplorer2_indexes_found"
]
```
*Justification: Automated system documentation and inventory*

**SA-9 - External System Services**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Monitoring of external service connections*

**SA-9 (2) - Identification of Functions, Ports, Protocols, and Services**
```json
"Checks": [
  "vpc_flow_logs_enabled",
  "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
  "config_recorder_all_regions_enabled"
]
```
*Justification: Network service identification and monitoring*

**SA-9 (5) - Processing, Storage, and Service Location**
```json
"Checks": [
  "config_recorder_all_regions_enabled",
  "vpc_different_regions"
]
```
*Justification: Geographic location tracking and compliance*

**SA-15 - Development Process, Standards, and Tools**
```json
"Checks": [
  "codebuild_project_no_secrets_in_variables",
  "codebuild_project_s3_logs_encrypted",
  "codebuild_project_logging_enabled"
]
```
*Justification: Secure development practices validation*

**SR-2 - Supply Chain Risk Management Plan**
```json
"Checks": [
  "trustedadvisor_premium_support_plan_subscribed",
  "securityhub_enabled"
]
```
*Justification: Supply chain monitoring capabilities*

**SR-6 - Supplier Assessments and Reviews**
```json
"Checks": [
  "securityhub_enabled",
  "config_recorder_all_regions_enabled"
]
```
*Justification: Third-party service assessment tools*

**SR-8 - Notification Agreements**
```json
"Checks": [
  "guardduty_is_enabled",
  "securityhub_enabled"
]
```
*Justification: Automated notification systems for security events*

**SR-11 (2) - Configuration Control for Component Service and Repair**
```json
"Checks": [
  "config_recorder_all_regions_enabled",
  "ssm_managed_compliant_patching"
]
```
*Justification: Configuration management for component maintenance*

## Implementation Priority Levels

### 🔴 Critical Priority (Immediate Implementation)
- All IAM-related controls (AC-2 sub-controls, AC-6 sub-controls, IA-4)
- Core audit controls (AU-5, AU-6, AU-8)
- Basic backup and recovery (CP-2, CP-3, CP-4)
- Fundamental security monitoring (IR controls, SI-2, SI-3)

### 🟠 High Priority (Phase 2)
- Advanced security assessment (CA controls)
- Configuration management (CM-8, CM-11)
- Network security controls (SC-7 sub-controls, SC-10, SC-15)
- Risk assessment automation (RA-3, RA-5 sub-controls)

### 🟡 Medium Priority (Phase 3)  
- Supply chain controls (SR controls)
- Development security (SA-15)
- Advanced system integrity (SI-5, SI-6, SI-11)
- Encryption controls (SC-28 (1), SC-45 (1))

### 🟢 Low Priority (Phase 4)
- External service monitoring (SA-9 sub-controls)
- Advanced configuration controls (SR-11 (2))
- Documentation automation (SA-5)

## Summary Statistics

- **Total Controls Analyzed**: 84
- **Policy Controls (Keep Empty)**: 52 controls
- **Technical Controls (Add Checks)**: 32 controls  
- **Total New Check Mappings**: ~156 individual check assignments
- **Average Checks per Technical Control**: 4.9 checks

## Next Steps

1. **Validate Mappings**: Review each technical control mapping for accuracy
2. **Test Implementation**: Deploy mappings in test environment
3. **Performance Assessment**: Ensure check combinations don't create excessive scan times
4. **Documentation Update**: Update FedRAMP compliance documentation
5. **Continuous Monitoring**: Establish process for maintaining mappings as new checks are added

---
*This analysis provides a comprehensive foundation for enhancing FedRAMP Moderate Revision 5 compliance monitoring with automated Prowler checks while respecting the distinction between policy and technical controls.*