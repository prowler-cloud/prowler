# AWS Prowler Checks for FedRAMP Moderate Revision 5 Mapping

## Executive Summary

This comprehensive catalog documents **572 AWS security checks** available in Prowler that can be mapped to FedRAMP Moderate Revision 5 controls. These checks span **77 AWS services** and are organized by security domains to facilitate compliance mapping.

### Key Statistics

- **Total AWS Checks**: 572
- **AWS Services Covered**: 77
- **Critical/High Severity Checks**: 171
- **FedRAMP-Relevant Control Families**: 7 primary families mapped

### Checks by FedRAMP Control Family

| Control Family | Check Count | Primary Focus |
|----------------|-------------|---------------|
| **AC - Access Control** | 183 | Identity management, permissions, authentication, authorization |
| **SC - System and Communications Protection** | 122 | Encryption, network security, SSL/TLS, data protection |
| **AU - Audit and Accountability** | 75 | Logging, monitoring, audit trails, CloudTrail |
| **CM - Configuration Management** | 45 | Secure configurations, compliance settings |
| **CP - Contingency Planning** | 34 | Backup, recovery, business continuity |
| **SI - System and Information Integrity** | 17 | Vulnerability scanning, threat detection |
| **RA - Risk Assessment** | 1 | Security assessments, compliance validation |

## Priority Services for FedRAMP Compliance

### Tier 1 - Critical Services (Most Checks)

1. **EC2 (69 checks)** - Instance security, network controls, encryption
2. **IAM (43 checks)** - Identity & access management, MFA, policies  
3. **RDS (34 checks)** - Database security, encryption, access control
4. **CloudWatch (22 checks)** - Log management, monitoring, alerting
5. **S3 (20 checks)** - Data protection, bucket security, access control

### Tier 2 - Important Services

6. **Cognito (16 checks)** - User authentication, password policies
7. **CloudTrail (14 checks)** - Audit logging, integrity, monitoring
8. **CloudFront (13 checks)** - Content delivery security, SSL/TLS
9. **Glue (12 checks)** - Data processing security, encryption
10. **OpenSearch (12 checks)** - Search service security, access control

## Critical and High Severity Checks by Service

### Most Critical Services (by severity count)

| Service | Total | Critical 🔴 | High 🟠 | Key Security Areas |
|---------|-------|-------------|---------|-------------------|
| **EC2** | 48 | 23 | 25 | Public exposure, network security, secrets |
| **IAM** | 19 | 4 | 15 | Root account, admin access, MFA |
| **S3** | 8 | 5 | 3 | Public buckets, access control |
| **ECS** | 8 | 1 | 7 | Container security, privileged access |
| **GuardDuty** | 6 | 0 | 6 | Threat detection, monitoring |
| **CloudTrail** | 5 | 4 | 1 | Audit logging, threat detection |
| **RDS** | 5 | 2 | 3 | Public access, encryption |

## Top 20 Critical Checks for Immediate FedRAMP Focus

### Access Control (AC)
1. `iam_root_mfa_enabled` - Ensure MFA is enabled for the root account
2. `iam_no_root_access_key` - Ensure no root account access key exists
3. `iam_root_hardware_mfa_enabled` - Ensure only hardware MFA is enabled for the root account
4. `s3_bucket_public_access` - Ensure there are no S3 buckets open to Everyone

### System Protection (SC)
5. `ec2_instance_secrets_user_data` - Find secrets in EC2 User Data
6. `ec2_ebs_public_snapshot` - Ensure there are no EBS Snapshots set as Public
7. `ec2_ami_public` - Ensure there are no EC2 AMIs set as Public
8. `kms_cmk_not_deleted_unintentionally` - AWS KMS keys should not be deleted unintentionally

### Audit & Accountability (AU)
9. `cloudtrail_logs_s3_bucket_is_not_publicly_accessible` - Ensure CloudTrail S3 bucket is not public
10. `cloudtrail_threat_detection_privilege_escalation` - Detect privilege escalation threats
11. `cloudtrail_threat_detection_llm_jacking` - Detect LLM Jacking threats

### Data Protection
12. `rds_instance_no_public_access` - Ensure RDS instances are not publicly accessible
13. `secretsmanager_not_publicly_accessible` - Ensure Secrets Manager secrets are not public
14. `sqs_queues_not_publicly_accessible` - Check if SQS queues have public policy
15. `ecr_repositories_not_publicly_accessible` - Ensure ECR repositories are not public

### Network Security
16. `glacier_vaults_policy_public_access` - Check if Glacier vaults allow public access
17. `documentdb_cluster_public_snapshot` - Check if DocumentDB snapshots are public
18. `dms_instance_no_public_access` - Ensure DMS instances are not publicly accessible

### Configuration Management
19. `codeartifact_packages_external_public_publishing_disabled` - Prevent external publishing
20. `awslambda_function_not_publicly_accessible` - Check Lambda function public access

## FedRAMP Control Family Mapping Guide

### AC - Access Control (183 checks)
**Key Services**: IAM (41), Cognito (16), EC2 (9), ECS (5)
**Primary Controls**: AC-2, AC-3, AC-6, AC-17
**Focus Areas**: User management, privilege management, remote access, least privilege

### AU - Audit and Accountability (75 checks) 
**Key Services**: CloudTrail (15), CloudWatch (18), S3 (5)
**Primary Controls**: AU-2, AU-3, AU-6, AU-9, AU-12
**Focus Areas**: Event logging, log protection, log monitoring, log retention

### SC - System and Communications Protection (122 checks)
**Key Services**: KMS (5), ELB/ELBv2 (6), VPC (4), CloudFront (4)
**Primary Controls**: SC-7, SC-8, SC-12, SC-13, SC-28
**Focus Areas**: Boundary protection, transmission protection, cryptographic protection

### CM - Configuration Management (45 checks)
**Key Services**: Config (2), EC2 (8), Various services
**Primary Controls**: CM-2, CM-6, CM-7, CM-8
**Focus Areas**: Baseline configurations, configuration settings, least functionality

### CP - Contingency Planning (34 checks)
**Key Services**: Backup (5), RDS (8), S3 (4), DynamoDB (3)
**Primary Controls**: CP-9, CP-10
**Focus Areas**: Information system backup, recovery and reconstitution

## Implementation Recommendations

### Phase 1: Foundation (Weeks 1-2)
- Implement all critical IAM checks (root account security, MFA)
- Configure CloudTrail logging and monitoring
- Secure S3 buckets and remove public access

### Phase 2: Core Services (Weeks 3-6)
- Implement EC2 security controls
- Configure RDS encryption and access controls
- Set up CloudWatch monitoring and alerting

### Phase 3: Advanced Controls (Weeks 7-12)
- Implement service-specific security controls
- Configure network security (VPC, security groups)
- Set up backup and recovery procedures

### Phase 4: Continuous Monitoring (Ongoing)
- Regular Prowler scans
- Automated remediation where possible
- Quarterly compliance assessments

## Automated Remediation Opportunities

Several checks include automated fixers:
- `kms_cmk_rotation_enabled_fixer.py` - Enable KMS key rotation
- `kms_cmk_not_deleted_unintentionally_fixer.py` - Prevent accidental KMS key deletion

## Compliance Mapping Notes

1. **Not all checks map 1:1 to FedRAMP controls** - Some checks support multiple controls
2. **Severity levels help prioritize** - Critical/High should be addressed first
3. **Service-specific controls** - Some AWS services have unique security considerations
4. **Continuous monitoring required** - FedRAMP requires ongoing assessment

## Next Steps

1. **Prioritize based on your environment** - Focus on services you actually use
2. **Map to specific FedRAMP controls** - Use this catalog to identify relevant checks
3. **Implement automated scanning** - Set up regular Prowler runs
4. **Create remediation procedures** - Document how to fix failing checks
5. **Monitor continuously** - FedRAMP requires ongoing compliance validation

---

*This catalog was generated from Prowler version with 572 AWS checks across 77 services. Check the latest Prowler documentation for updates.*