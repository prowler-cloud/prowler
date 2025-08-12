# FedRAMP 20x Key Security Indicators (KSIs) Compliance with Prowler

## Overview

This guide explains how to use Prowler to assess your cloud environment against the FedRAMP 20x Key Security Indicators (KSIs). These KSIs represent core security indicators for cloud service providers, focusing on automation, continuous monitoring, and cloud-native security principles as part of the FedRAMP 20x Phase One pilot program.

## What are FedRAMP 20x KSIs?

FedRAMP 20x is a modernization initiative aimed at automating the FedRAMP authorization process. The Key Security Indicators are 10 critical security areas that cloud service providers must address:

1. **KSI-CED**: Cybersecurity Education
2. **KSI-CMT**: Change Management
3. **KSI-CNA**: Cloud Native Architecture
4. **KSI-IAM**: Identity and Access Management
5. **KSI-INR**: Incident Reporting
6. **KSI-MLA**: Monitoring, Logging, and Auditing
7. **KSI-PIY**: Policy and Inventory
8. **KSI-RPL**: Recovery Planning
9. **KSI-SVC**: Service Configuration
10. **KSI-TPR**: Third-Party Information Resources

## Prerequisites

- Prowler v4.0+ installed
- Cloud provider credentials configured (AWS, Azure, or GCP)
- The FedRAMP 20x KSI compliance frameworks installed (included in this repository)

## Quick Start

### Check FedRAMP 20x KSI Compliance for AWS

```bash
# Run a focused scan for FedRAMP 20x KSIs only
prowler aws --compliance fedramp_20x_ksi_aws

# Run with dashboard visualization
prowler aws --compliance fedramp_20x_ksi_aws --dashboard

# Output to specific formats
prowler aws --compliance fedramp_20x_ksi_aws --output-formats html,csv,json
```

### Check FedRAMP 20x KSI Compliance for Azure

```bash
# Run a focused scan for FedRAMP 20x KSIs only
prowler azure --compliance fedramp_20x_ksi_azure

# With specific subscription
prowler azure --subscription-ids <SUBSCRIPTION_ID> --compliance fedramp_20x_ksi_azure
```

### Check FedRAMP 20x KSI Compliance for GCP

```bash
# Run a focused scan for FedRAMP 20x KSIs only
prowler gcp --compliance fedramp_20x_ksi_gcp

# With specific project
prowler gcp --project-ids <PROJECT_ID> --compliance fedramp_20x_ksi_gcp
```

## Understanding the Results

### Terminal Output

When you run a FedRAMP 20x KSI compliance scan, you'll see:

```
Compliance Status of FEDRAMP_20X_KSI_AWS Framework:
╭─────────────────────────────────────────────────────────╮
│ 22.5% (89) FAIL | 75.2% (298) PASS | 2.3% (9) MUTED    │
╰─────────────────────────────────────────────────────────╯
```

### Dashboard View

Access the dashboard at `http://localhost:3000/compliance` to see:
- Overall FedRAMP 20x KSI compliance score
- Individual KSI scores and status
- Detailed findings for each requirement
- Download compliance reports

### Compliance Reports

Reports are generated in the output folder:
```
output/
├── compliance/
│   └── prowler-compliance-fedramp_20x_ksi_aws-<timestamp>.csv
└── prowler-output-<timestamp>.html
```

## KSI Breakdown and Key Checks

### KSI-IAM: Identity and Access Management
Focuses on MFA, least privilege, and zero trust principles.

Key checks include:
- MFA enabled for all users with console access
- No root account access keys
- Password policy compliance
- IAM policies without administrative privileges

```bash
# Run only IAM-related checks
prowler aws -c iam_root_mfa_enabled iam_user_mfa_enabled_console_access iam_password_policy_minimum_length_14
```

### KSI-MLA: Monitoring, Logging, and Auditing
Ensures comprehensive logging and continuous monitoring.

Key checks include:
- CloudTrail/Activity logs enabled in all regions
- Log retention policies configured
- VPC Flow Logs/Network flow logs enabled
- Security monitoring services active

```bash
# Run only monitoring and logging checks
prowler aws -c cloudtrail_multi_region_enabled cloudwatch_log_group_retention_policy_specific_days_enabled vpc_flow_logs_enabled
```

### KSI-CMT: Change Management
Tracks and documents all system changes.

Key checks include:
- Configuration management services enabled
- Change tracking and auditing
- Patch management compliance

### KSI-SVC: Service Configuration
Ensures proper encryption and secure configurations.

Key checks include:
- Encryption at rest and in transit
- KMS key rotation enabled
- Secure transport policies
- Certificate management

## Automation and CI/CD Integration

### GitHub Actions Example

```yaml
name: FedRAMP 20x KSI Compliance Check
on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Prowler FedRAMP 20x KSI Scan
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          pip install prowler
          prowler aws --compliance fedramp_20x_ksi_aws --output-formats json
          
      - name: Upload Compliance Report
        uses: actions/upload-artifact@v3
        with:
          name: fedramp-20x-compliance-report
          path: output/
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('FedRAMP 20x KSI Compliance Check') {
            steps {
                sh '''
                    prowler aws --compliance fedramp_20x_ksi_aws \
                      --output-formats json,html \
                      --output-directory ${WORKSPACE}/compliance-reports
                '''
            }
        }
        
        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'compliance-reports/**/*', 
                                 allowEmptyArchive: false
            }
        }
    }
}
```

## Best Practices

### 1. Regular Scanning
Schedule automated scans to maintain continuous compliance:
```bash
# Add to crontab for daily scans
0 2 * * * prowler aws --compliance fedramp_20x_ksi_aws --output-directory /var/log/prowler/
```

### 2. Focus on Critical KSIs
Prioritize remediation based on KSI importance:
```bash
# Check critical security KSIs first
prowler aws --compliance fedramp_20x_ksi_aws --severity critical high
```

### 3. Multi-Account/Multi-Region
Ensure comprehensive coverage:
```bash
# AWS Organizations
prowler aws --compliance fedramp_20x_ksi_aws --role ProwlerRole --organizations

# All Azure subscriptions
prowler azure --compliance fedramp_20x_ksi_azure --subscription-ids ALL

# All GCP projects
prowler gcp --compliance fedramp_20x_ksi_gcp --project-ids ALL
```

### 4. Exception Management
Use mutelist for approved exceptions:
```yaml
# mutelist.yaml
Mutelist:
  Accounts:
    - "123456789012"
  Checks:
    iam_user_hardware_mfa_enabled:
      - Reason: "Service accounts don't support hardware MFA"
        Resources:
          - "arn:aws:iam::*:user/service-*"
```

## Mapping to NIST Controls

Each KSI maps to specific NIST 800-53 controls:

| KSI | NIST Controls | Focus Area |
|-----|---------------|------------|
| KSI-CED | AT-2, AT-3, AT-4 | Training & Awareness |
| KSI-CMT | AU-2, CM-2 through CM-9, SI-2, SI-3 | Configuration Management |
| KSI-CNA | AC-17.3, CA-9, CM-2, SC-5, SC-7 | Network Architecture |
| KSI-IAM | AC-2, AC-3, AC-4, AC-6, IA-2, IA-5, IA-8 | Access Control |
| KSI-INR | IR-4, IR-6 | Incident Response |
| KSI-MLA | AU-2, CA-7, RA-5 | Auditing & Monitoring |
| KSI-PIY | CM-8, PL-2 | Asset Management |
| KSI-RPL | CP-2, CP-9, CP-10 | Contingency Planning |
| KSI-SVC | SC-7, SC-13, CM-6 | System Protection |
| KSI-TPR | SA-9, RA-5 | Supply Chain |

## Troubleshooting

### Frameworks Not Appearing
If the FedRAMP 20x KSI frameworks don't appear:

1. Verify the framework files exist:
```bash
ls -la prowler/compliance/*/fedramp_20x_ksi_*.json
```

2. Check framework is recognized:
```bash
prowler aws --list-compliance | grep fedramp_20x
```

3. Clear cache and rescan:
```bash
rm -rf ~/.prowler/
prowler aws --compliance fedramp_20x_ksi_aws
```

### Low Compliance Scores
FedRAMP 20x emphasizes automation and continuous monitoring. Low scores often indicate:
- Missing monitoring/logging services
- Lack of automated configuration management
- Manual processes that should be automated

Focus on implementing:
- AWS: CloudTrail, Config, Systems Manager, GuardDuty, Security Hub
- Azure: Defender, Monitor, Policy, Activity Logs
- GCP: Cloud Asset Inventory, Security Command Center, Cloud Logging

## Additional Resources

- [FedRAMP 20x Official Documentation](https://www.fedramp.gov/20x/)
- [FedRAMP 20x Goals](https://www.fedramp.gov/20x/goals/)
- [FedRAMP KSI GitHub Repository](https://github.com/FedRAMP/docs)
- [Prowler Documentation](https://docs.prowler.cloud)

## Contributing

To contribute improvements to the FedRAMP 20x KSI compliance frameworks:

1. Fork the repository
2. Update the relevant JSON files in `prowler/compliance/`
3. Test your changes thoroughly
4. Submit a pull request with a clear description

## Support

For issues specific to FedRAMP 20x KSI compliance:
- Open an issue on [Prowler GitHub](https://github.com/prowlercloud/prowler/issues)
- Reference this README and the specific KSI having issues
- Include the output of `prowler --version` and your compliance scan results

## License

The FedRAMP 20x KSI compliance frameworks are based on public FedRAMP documentation and are provided as-is to help organizations assess their cloud security posture against FedRAMP 20x requirements.