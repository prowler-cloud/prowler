from prowler.lib.check.compliance_models import (
    AWS_Well_Architected_Requirement_Attribute,
    CIS_Requirement_Attribute,
    Compliance,
    Compliance_Requirement,
    ENS_Requirement_Attribute,
    ENS_Requirement_Attribute_Nivel,
    ENS_Requirement_Attribute_Tipos,
    Generic_Compliance_Requirement_Attribute,
    ISO27001_2013_Requirement_Attribute,
    KISA_ISMSP_Requirement_Attribute,
    Mitre_Requirement,
    Mitre_Requirement_Attribute_AWS,
    Mitre_Requirement_Attribute_Azure,
    Mitre_Requirement_Attribute_GCP,
)

CIS_1_4_AWS_NAME = "cis_1.4_aws"
CIS_1_4_AWS = Compliance(
    Framework="CIS",
    Provider="AWS",
    Version="1.4",
    Description="The CIS Benchmark for CIS Amazon Web Services Foundations Benchmark, v1.4.0, Level 1 and 2 provides prescriptive guidance for configuring security options for a subset of Amazon Web Services. It has an emphasis on foundational, testable, and architecture agnostic settings",
    Requirements=[
        Compliance_Requirement(
            Checks=["test-check-id"],
            Id="2.1.3",
            Description="Ensure MFA Delete is enabled on S3 buckets",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1. Simple Storage Service (S3)",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                    RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                    ImpactStatement="",
                    RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                    AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                    AdditionalInformation="",
                    References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                )
            ],
        ),
        Compliance_Requirement(
            Checks=[],
            Id="2.1.4",
            Description="Ensure MFA Delete is enabled on S3 buckets",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1. Simple Storage Service (S3)",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                    RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                    ImpactStatement="",
                    RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                    AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                    AdditionalInformation="",
                    References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                )
            ],
        ),
    ],
)
CIS_2_0_AZURE_NAME = "cis_2.0_azure"
CIS_2_0_AZURE = Compliance(
    Framework="CIS",
    Provider="Azure",
    Version="2.0",
    Description="The CIS Azure Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Azure with an emphasis on foundational, testable, and architecture agnostic settings.",
    Requirements=[
        Compliance_Requirement(
            Checks=["test-check-id"],
            Id="2.1.3",
            Description="Ensure That Microsoft Defender for Databases Is Set To 'On'",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1 Microsoft Defender for Cloud",
                    Profile="Level 2",
                    AssessmentStatus="Manual",
                    Description="Turning on Microsoft Defender for Databases enables threat detection for the instances running your database software. This provides threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. Instead of being enabled on services like Platform as a Service (PaaS), this implementation will run within your instances as Infrastructure as a Service (IaaS) on the Operating Systems hosting your databases.",
                    RationaleStatement="Enabling Microsoft Defender for Azure SQL Databases allows your organization more granular control of the infrastructure running your database software. Instead of waiting on Microsoft release updates or other similar processes, you can manage them yourself. Threat detection is provided by the Microsoft Security Response Center (MSRC).",
                    ImpactStatement="Running Defender on Infrastructure as a service (IaaS) may incur increased costs associated with running the service and the instance it is on. Similarly, you will need qualified personnel to maintain the operating system and software updates. If it is not maintained, security patches will not be applied and it may be open to vulnerabilities.",
                    RemediationProcedure="From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Set Databases Status to On 6. Select Save Review the chosen pricing tier. For the Azure Databases resource review the different plan information and choose one that fits the needs of your organization. From Azure CLI Run the following commands: az security pricing create -n 'SqlServers' --tier 'Standard' az security pricing create -n 'SqlServerVirtualMachines' --tier 'Standard' az security pricing create -n 'OpenSourceRelationalDatabases' --tier 'Standard' az security pricing create -n 'CosmosDbs' --tier 'Standard' From Azure PowerShell Run the following commands: Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'OpenSourceRelationalDatabases' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard'",
                    AuditProcedure="From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Ensure Databases Status is set to On 6. Review the chosen pricing tier From Azure CLI Ensure the output of the below commands is Standard az security pricing show -n 'SqlServers' az security pricing show -n 'SqlServerVirtualMachines' az security pricing show -n 'OpenSourceRelationalDatabases' az security pricing show -n 'CosmosDbs' If the output of any of the above commands shows pricingTier with a value of Free, the setting is out of compliance. From PowerShell Connect-AzAccount Get-AzSecurityPricing |select-object Name,PricingTier |where-object {$_.Name -match 'Sql' -or $_.Name -match 'Cosmos' -or $_.Name -match 'OpenSource'} Ensure the output shows Standard for each database type under the PricingTier column. Any that show Free are considered out of compliance.",
                    AdditionalInformation="",
                    DefaultValue="By default, Microsoft Defender plan is off.",
                    References="https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql?view=azuresql:https://docs.microsoft.com/en-us/azure/defender-for-cloud/quickstart-enable-database-protections:https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-usage:https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities:https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list:https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-1-enable-threat-detection-capabilities",
                )
            ],
        ),
        Compliance_Requirement(
            Checks=[],
            Id="2.1.4",
            Description="Ensure That Microsoft Defender for Databases Is Set To 'On'",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1 Microsoft Defender for Cloud",
                    Profile="Level 2",
                    AssessmentStatus="Manual",
                    Description="Turning on Microsoft Defender for Databases enables threat detection for the instances running your database software. This provides threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. Instead of being enabled on services like Platform as a Service (PaaS), this implementation will run within your instances as Infrastructure as a Service (IaaS) on the Operating Systems hosting your databases.",
                    RationaleStatement="Enabling Microsoft Defender for Azure SQL Databases allows your organization more granular control of the infrastructure running your database software. Instead of waiting on Microsoft release updates or other similar processes, you can manage them yourself. Threat detection is provided by the Microsoft Security Response Center (MSRC).",
                    ImpactStatement="Running Defender on Infrastructure as a service (IaaS) may incur increased costs associated with running the service and the instance it is on. Similarly, you will need qualified personnel to maintain the operating system and software updates. If it is not maintained, security patches will not be applied and it may be open to vulnerabilities.",
                    RemediationProcedure="From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Set Databases Status to On 6. Select Save Review the chosen pricing tier. For the Azure Databases resource review the different plan information and choose one that fits the needs of your organization. From Azure CLI Run the following commands: az security pricing create -n 'SqlServers' --tier 'Standard' az security pricing create -n 'SqlServerVirtualMachines' --tier 'Standard' az security pricing create -n 'OpenSourceRelationalDatabases' --tier 'Standard' az security pricing create -n 'CosmosDbs' --tier 'Standard' From Azure PowerShell Run the following commands: Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'OpenSourceRelationalDatabases' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard'",
                    AuditProcedure="From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Ensure Databases Status is set to On 6. Review the chosen pricing tier From Azure CLI Ensure the output of the below commands is Standard az security pricing show -n 'SqlServers' az security pricing show -n 'SqlServerVirtualMachines' az security pricing show -n 'OpenSourceRelationalDatabases' az security pricing show -n 'CosmosDbs' If the output of any of the above commands shows pricingTier with a value of Free, the setting is out of compliance. From PowerShell Connect-AzAccount Get-AzSecurityPricing |select-object Name,PricingTier |where-object {$_.Name -match 'Sql' -or $_.Name -match 'Cosmos' -or $_.Name -match 'OpenSource'} Ensure the output shows Standard for each database type under the PricingTier column. Any that show Free are considered out of compliance.",
                    AdditionalInformation="",
                    DefaultValue="By default, Microsoft Defender plan is off.",
                    References="https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql?view=azuresql:https://docs.microsoft.com/en-us/azure/defender-for-cloud/quickstart-enable-database-protections:https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-usage:https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities:https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list:https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-1-enable-threat-detection-capabilities",
                )
            ],
        ),
    ],
)
CIS_2_0_GCP_NAME = "cis_2.0_gcp"
CIS_2_0_GCP = Compliance(
    Framework="CIS",
    Provider="GCP",
    Version="2.0",
    Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
    Requirements=[
        Compliance_Requirement(
            Checks=["apikeys_key_exits"],
            Id="2.13",
            Description="Ensure That Microsoft Defender for Databases Is Set To 'On'",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2. Logging and Monitoring",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="GCP Cloud Asset Inventory is services that provides a historical view of GCP resources and IAM policies through a time-series database. The information recorded includes metadata on Google Cloud resources, metadata on policies set on Google Cloud projects or resources, and runtime information gathered within a Google Cloud resource.",
                    RationaleStatement="The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.  It is recommended GCP Cloud Asset Inventory be enabled for all GCP projects.",
                    ImpactStatement="",
                    RemediationProcedure="**From Google Cloud Console**  Enable the Cloud Asset API:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Click the `ENABLE` button.  **From Google Cloud CLI**  Enable the Cloud Asset API:  1. Enable the Cloud Asset API through the services interface: ``` gcloud services enable cloudasset.googleapis.com ```",
                    AuditProcedure="**From Google Cloud Console**  Ensure that the Cloud Asset API is enabled:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Ensure that `API Enabled` is displayed.  **From Google Cloud CLI**  Ensure that the Cloud Asset API is enabled:  1. Query enabled services: ``` gcloud services list --enabled --filter=name:cloudasset.googleapis.com ``` If the API is listed, then it is enabled. If the response is `Listed 0 items` the API is not enabled.",
                    AdditionalInformation="Additional info - Cloud Asset Inventory only keeps a five-week history of Google Cloud asset metadata. If a longer history is desired, automation to export the history to Cloud Storage or BigQuery should be evaluated.",
                    References="https://cloud.google.com/asset-inventory/docs",
                )
            ],
        ),
        Compliance_Requirement(
            Checks=[],
            Id="2.14",
            Description="Ensure That Microsoft Defender for Databases Is Set To 'On'",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2. Logging and Monitoring",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="GCP Cloud Asset Inventory is services that provides a historical view of GCP resources and IAM policies through a time-series database. The information recorded includes metadata on Google Cloud resources, metadata on policies set on Google Cloud projects or resources, and runtime information gathered within a Google Cloud resource.",
                    RationaleStatement="The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.  It is recommended GCP Cloud Asset Inventory be enabled for all GCP projects.",
                    ImpactStatement="",
                    RemediationProcedure="**From Google Cloud Console**  Enable the Cloud Asset API:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Click the `ENABLE` button.  **From Google Cloud CLI**  Enable the Cloud Asset API:  1. Enable the Cloud Asset API through the services interface: ``` gcloud services enable cloudasset.googleapis.com ```",
                    AuditProcedure="**From Google Cloud Console**  Ensure that the Cloud Asset API is enabled:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Ensure that `API Enabled` is displayed.  **From Google Cloud CLI**  Ensure that the Cloud Asset API is enabled:  1. Query enabled services: ``` gcloud services list --enabled --filter=name:cloudasset.googleapis.com ``` If the API is listed, then it is enabled. If the response is `Listed 0 items` the API is not enabled.",
                    AdditionalInformation="Additional info - Cloud Asset Inventory only keeps a five-week history of Google Cloud asset metadata. If a longer history is desired, automation to export the history to Cloud Storage or BigQuery should be evaluated.",
                    References="https://cloud.google.com/asset-inventory/docs",
                )
            ],
        ),
    ],
)
CIS_1_8_KUBERNETES_NAME = "cis_2.0_kubernetes"
CIS_1_8_KUBERNETES = Compliance(
    Framework="CIS",
    Provider="Kubernetes",
    Version="1.8",
    Description="This CIS Kubernetes Benchmark provides prescriptive guidance for establishing a secure configuration posture for Kubernetes v1.27.",
    Requirements=[
        Compliance_Requirement(
            Checks=["apiserver_always_pull_images_plugin"],
            Id="1.1.3",
            Description="Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="1.1 Control Plane Node Configuration Files",
                    Profile="Level 1 - Master Node",
                    AssessmentStatus="Automated",
                    Description="Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.",
                    RationaleStatement="The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
                    ImpactStatement="",
                    RemediationProcedure="Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```",
                    AuditProcedure="Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml ```  Verify that the permissions are `600` or more restrictive.",
                    AdditionalInformation="",
                    References="https://kubernetes.io/docs/admin/kube-apiserver/",
                    DefaultValue="By default, the `kube-controller-manager.yaml` file has permissions of `640`.",
                )
            ],
        ),
        Compliance_Requirement(
            Checks=[],
            Id="1.1.4",
            Description="Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="1.1 Control Plane Node Configuration Files",
                    Profile="Level 1 - Master Node",
                    AssessmentStatus="Automated",
                    Description="Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.",
                    RationaleStatement="The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
                    ImpactStatement="",
                    RemediationProcedure="Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```",
                    AuditProcedure="Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml ```  Verify that the permissions are `600` or more restrictive.",
                    AdditionalInformation="",
                    References="https://kubernetes.io/docs/admin/kube-apiserver/",
                    DefaultValue="By default, the `kube-controller-manager.yaml` file has permissions of `640`.",
                )
            ],
        ),
    ],
)
CIS_1_5_AWS_NAME = "cis_1.5_aws"
CIS_1_5_AWS = Compliance(
    Framework="CIS",
    Provider="AWS",
    Version="1.5",
    Description="The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services with an emphasis on foundational, testable, and architecture agnostic settings.",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
            Id="2.1.3",
            Description="Ensure MFA Delete is enabled on S3 buckets",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1. Simple Storage Service (S3)",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                    RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                    ImpactStatement="",
                    RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                    AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                    AdditionalInformation="",
                    References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                )
            ],
        )
    ],
)

MITRE_ATTACK_AWS_NAME = "mitre_attack_aws"
MITRE_ATTACK_AWS = Compliance(
    Framework="MITRE-ATTACK",
    Provider="AWS",
    Version="",
    Description="MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
    Requirements=[
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1190",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_AWS(
                    AWSService="AWS CloudEndure Disaster Recovery",
                    Category="Respond",
                    Value="Significant",
                    Comment="AWS CloudEndure Disaster Recovery enables the replication and recovery of servers into AWS Cloud. In the event that a public-facing application or server is compromised, AWS CloudEndure can be used to provision an instance of the server from a previous point in time within minutes. As a result, this mapping is given a score of Significant.",
                )
            ],
            Checks=[
                "drs_job_exist",
                "config_recorder_all_regions_enabled",
                "rds_instance_minor_version_upgrade_enabled",
                "rds_instance_backup_enabled",
                "securityhub_enabled",
                "elbv2_waf_acl_attached",
                "guardduty_is_enabled",
                "inspector2_is_enabled",
                "inspector2_active_findings_exist",
                "awslambda_function_not_publicly_accessible",
                "ec2_instance_public_ip",
            ],
        ),
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1193",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_AWS(
                    AWSService="AWS CloudEndure Disaster Recovery",
                    Category="Respond",
                    Value="Significant",
                    Comment="AWS CloudEndure Disaster Recovery enables the replication and recovery of servers into AWS Cloud. In the event that a public-facing application or server is compromised, AWS CloudEndure can be used to provision an instance of the server from a previous point in time within minutes. As a result, this mapping is given a score of Significant.",
                )
            ],
            Checks=[],
        ),
    ],
)
MITRE_ATTACK_AZURE_NAME = "mitre_attack_azure"
MITRE_ATTACK_AZURE = Compliance(
    Framework="MITRE-ATTACK",
    Provider="Azure",
    Version="",
    Description="MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
    Requirements=[
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1190",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_Azure(
                    AzureService="Azure SQL Database",
                    Category="Detect",
                    Value="Minimal",
                    Comment="This control may alert on usage of faulty SQL statements. This generates an alert for a possible SQL injection by an application. Alerts may not be generated on usage of valid SQL statements by attackers for malicious purposes.",
                )
            ],
            Checks=[
                "aks_clusters_created_with_private_nodes",
                "aks_clusters_public_access_disabled",
                "app_ensure_java_version_is_latest",
                "app_ensure_php_version_is_latest",
                "app_ensure_python_version_is_latest",
                "defender_assessments_vm_endpoint_protection_installed",
                "defender_assessments_vm_endpoint_protection_installed",
                "defender_auto_provisioning_log_analytics_agent_vms_on",
                "defender_auto_provisioning_vulnerabilty_assessments_machines_on",
                "defender_container_images_resolved_vulnerabilities",
                "defender_container_images_scan_enabled",
                "defender_ensure_defender_for_app_services_is_on",
                "defender_ensure_defender_for_arm_is_on",
                "defender_ensure_defender_for_azure_sql_databases_is_on",
                "defender_ensure_defender_for_containers_is_on",
                "defender_ensure_defender_for_cosmosdb_is_on",
                "defender_ensure_defender_for_databases_is_on",
                "defender_ensure_defender_for_dns_is_on",
                "defender_ensure_defender_for_keyvault_is_on",
                "defender_ensure_defender_for_os_relational_databases_is_on",
                "defender_ensure_defender_for_server_is_on",
                "defender_ensure_defender_for_sql_servers_is_on",
                "defender_ensure_defender_for_storage_is_on",
                "defender_ensure_iot_hub_defender_is_on",
                "defender_ensure_mcas_is_enabled",
                "defender_ensure_notify_alerts_severity_is_high",
                "defender_ensure_notify_emails_to_owners",
                "defender_ensure_system_updates_are_applied",
                "defender_ensure_wdatp_is_enabled",
            ],
        ),
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1191",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_Azure(
                    AzureService="Azure SQL Database",
                    Category="Detect",
                    Value="Minimal",
                    Comment="This control may alert on usage of faulty SQL statements. This generates an alert for a possible SQL injection by an application. Alerts may not be generated on usage of valid SQL statements by attackers for malicious purposes.",
                )
            ],
            Checks=[],
        ),
    ],
)
MITRE_ATTACK_GCP_NAME = "mitre_attack_gcp"
MITRE_ATTACK_GCP = Compliance(
    Framework="MITRE-ATTACK",
    Provider="GCP",
    Version="",
    Description="MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
    Requirements=[
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1190",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_GCP(
                    GCPService="Artifact Registry",
                    Category="Protect",
                    Value="Partial",
                    Comment="Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.",
                )
            ],
            Checks=[
                "cloudsql_instance_public_access",
                "cloudsql_instance_public_ip",
                "cloudstorage_bucket_public_access",
                "compute_firewall_rdp_access_from_the_internet_allowed",
                "compute_firewall_ssh_access_from_the_internet_allowed",
                "compute_instance_public_ip",
                "compute_public_address_shodan",
                "kms_key_not_publicly_accessible",
            ],
        ),
        Mitre_Requirement(
            Name="Exploit Public-Facing Application",
            Id="T1191",
            Tactics=["Initial Access"],
            SubTechniques=[],
            Description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            Platforms=["Containers", "IaaS", "Linux", "Network", "Windows", "macOS"],
            TechniqueURL="https://attack.mitre.org/techniques/T1190/",
            Attributes=[
                Mitre_Requirement_Attribute_GCP(
                    GCPService="Artifact Registry",
                    Category="Protect",
                    Value="Partial",
                    Comment="Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.",
                )
            ],
            Checks=[],
        ),
    ],
)
ENS_RD2022_AWS_NAME = "ens_rd2022_aws"
ENS_RD2022_AWS = Compliance(
    Framework="ENS",
    Provider="AWS",
    Version="RD2022",
    Description="The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.",
    Requirements=[
        Compliance_Requirement(
            Id="op.exp.8.aws.ct.3",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=["cloudtrail_log_file_validation_enabled"],
        ),
        Compliance_Requirement(
            Id="op.exp.8.aws.ct.4",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=[],
        ),
    ],
)
ENS_RD2022_AZURE_NAME = "ens_rd2022_azure"
ENS_RD2022_AZURE = Compliance(
    Framework="ENS",
    Provider="Azure",
    Version="RD2022",
    Description="The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.",
    Requirements=[
        Compliance_Requirement(
            Id="op.exp.8.azure.ct.3",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=["cloudtrail_log_file_validation_enabled"],
        ),
        Compliance_Requirement(
            Id="op.exp.8.azure.ct.4",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=[],
        ),
    ],
)
ENS_RD2022_GCP_NAME = "ens_rd2022_gcp"
ENS_RD2022_GCP = Compliance(
    Framework="ENS",
    Provider="GCP",
    Version="RD2022",
    Description="The accreditation scheme of the ENS (National Security Scheme) has been developed by the Ministry of Finance and Public Administrations and the CCN (National Cryptological Center). This includes the basic principles and minimum requirements necessary for the adequate protection of information.",
    Requirements=[
        Compliance_Requirement(
            Id="op.exp.8.gcp.ct.3",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=["cloudtrail_log_file_validation_enabled"],
        ),
        Compliance_Requirement(
            Id="op.exp.8.gcp.ct.4",
            Description="Registro de actividad",
            Name=None,
            Attributes=[
                ENS_Requirement_Attribute(
                    IdGrupoControl="op.exp.8",
                    Marco="operacional",
                    Categoria="explotación",
                    DescripcionControl="Habilitar la validación de archivos en todos los trails, evitando así que estos se vean modificados o eliminados.",
                    Tipo=ENS_Requirement_Attribute_Tipos.requisito,
                    Nivel=ENS_Requirement_Attribute_Nivel.alto,
                    Dimensiones=["trazabilidad"],
                    ModoEjecucion="automático",
                    Dependencias=[],
                )
            ],
            Checks=[],
        ),
    ],
)
NOT_PRESENT_COMPLIANCE_NAME = "not_present_compliance_name"
NOT_PRESENT_COMPLIANCE = Compliance(
    Framework="NOT_EXISTENT",
    Provider="NOT_EXISTENT",
    Version="NOT_EXISTENT",
    Description="NOT_EXISTENT",
    Requirements=[],
)
AWS_WELL_ARCHITECTED_NAME = "aws_well_architected_framework_security_pillar_aws"
AWS_WELL_ARCHITECTED = Compliance(
    Framework="AWS-Well-Architected-Framework-Security-Pillar",
    Provider="AWS",
    Version="",
    Description="Best Practices for AWS Well-Architected Framework Security Pillar. The focus of this framework is the security pillar of the AWS Well-Architected Framework. It provides guidance to help you apply best practices, current recommendations in the design, delivery, and maintenance of secure AWS workloads.",
    Requirements=[
        Compliance_Requirement(
            Id="SEC01-BP01",
            Description="Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
            Name=None,
            Attributes=[
                AWS_Well_Architected_Requirement_Attribute(
                    Name="SEC01-BP01 Separate workloads using accounts",
                    WellArchitectedQuestionId="securely-operate",
                    WellArchitectedPracticeId="sec_securely_operate_multi_accounts",
                    Section="Security foundations",
                    SubSection="AWS account management and separation",
                    LevelOfRisk="High",
                    AssessmentMethod="Automated",
                    Description="Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
                    ImplementationGuidanceUrl="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_multi_accounts.html#implementation-guidance.",
                )
            ],
            Checks=["organizations_account_part_of_organizations"],
        ),
        Compliance_Requirement(
            Id="SEC01-BP02",
            Description="Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
            Name=None,
            Attributes=[
                AWS_Well_Architected_Requirement_Attribute(
                    Name="SEC01-BP01 Separate workloads using accounts",
                    WellArchitectedQuestionId="securely-operate",
                    WellArchitectedPracticeId="sec_securely_operate_multi_accounts",
                    Section="Security foundations",
                    SubSection="AWS account management and separation",
                    LevelOfRisk="High",
                    AssessmentMethod="Automated",
                    Description="Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
                    ImplementationGuidanceUrl="https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_multi_accounts.html#implementation-guidance.",
                )
            ],
            Checks=[],
        ),
    ],
)
AWISO27001_2013_AWS_NAME = "iso27001_2013_aws"
ISO27001_2013_AWS = Compliance(
    Framework="ISO27001",
    Provider="AWS",
    Version="2013",
    Description="ISO (the International Organization for Standardization) and IEC (the International Electrotechnical Commission) form the specialized system for worldwide standardization. National bodies that are members of ISO or IEC participate in the development of International Standards through technical committees established by the respective organization to deal with particular fields of technical activity. ISO and IEC technical committees collaborate in fields of mutual interest. Other international organizations, governmental and non-governmental, in liaison with ISO and IEC, also take part in the work.",
    Requirements=[
        Compliance_Requirement(
            Id="A.10.1",
            Description="Setup Encryption at rest for RDS instances",
            Name="Cryptographic Controls",
            Attributes=[
                ISO27001_2013_Requirement_Attribute(
                    Category="A.10 Cryptography",
                    Objetive_ID="A.10.1",
                    Objetive_Name="Cryptographic Controls",
                    Check_Summary="Setup Encryption at rest for RDS instances",
                )
            ],
            Checks=["rds_instance_storage_encrypted"],
        ),
    ],
)
ISO27001_2013_AWS_NAME = "iso27001_2013_aws"
ISO27001_2013_AWS = Compliance(
    Framework="ISO27001",
    Provider="AWS",
    Version="2013",
    Description="ISO (the International Organization for Standardization) and IEC (the International Electrotechnical Commission) form the specialized system for worldwide standardization. National bodies that are members of ISO or IEC participate in the development of International Standards through technical committees established by the respective organization to deal with particular fields of technical activity. ISO and IEC technical committees collaborate in fields of mutual interest. Other international organizations, governmental and non-governmental, in liaison with ISO and IEC, also take part in the work.",
    Requirements=[
        Compliance_Requirement(
            Id="A.10.1",
            Description="Setup Encryption at rest for RDS instances",
            Name="Cryptographic Controls",
            Attributes=[
                ISO27001_2013_Requirement_Attribute(
                    Category="A.10 Cryptography",
                    Objetive_ID="A.10.1",
                    Objetive_Name="Cryptographic Controls",
                    Check_Summary="Setup Encryption at rest for RDS instances",
                )
            ],
            Checks=["rds_instance_storage_encrypted"],
        ),
        Compliance_Requirement(
            Id="A.10.2",
            Description="Setup Encryption at rest for RDS instances",
            Name="Cryptographic Controls",
            Attributes=[
                ISO27001_2013_Requirement_Attribute(
                    Category="A.10 Cryptography",
                    Objetive_ID="A.10.1",
                    Objetive_Name="Cryptographic Controls",
                    Check_Summary="Setup Encryption at rest for RDS instances",
                )
            ],
            Checks=[],
        ),
    ],
)
NIST_800_53_REVISION_4_AWS_NAME = "nist_800_53_revision_4_aws"
NIST_800_53_REVISION_4_AWS = Compliance(
    Framework="NIST-800-53-Revision-4",
    Provider="AWS",
    Version="",
    Description="NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
    Requirements=[
        Compliance_Requirement(
            Id="ac_2_4",
            Description="Account Management",
            Name="The information system automatically audits account creation, modification, enabling, disabling, and removal actions, and notifies [Assignment: organization-defined personnel or roles].",
            Attributes=[
                Generic_Compliance_Requirement_Attribute(
                    ItemId="ac_2_4",
                    Section="Access Control (AC)",
                    SubSection="Account Management (AC-2)",
                    Service="aws",
                )
            ],
            Checks=[
                "cloudtrail_multi_region_enabled",
                "cloudtrail_multi_region_enabled",
                "cloudtrail_cloudwatch_logging_enabled",
                "cloudwatch_changes_to_network_acls_alarm_configured",
                "cloudwatch_changes_to_network_gateways_alarm_configured",
                "cloudwatch_changes_to_network_route_tables_alarm_configured",
                "cloudwatch_changes_to_vpcs_alarm_configured",
                "guardduty_is_enabled",
                "rds_instance_integration_cloudwatch_logs",
                "redshift_cluster_audit_logging",
                "securityhub_enabled",
            ],
        ),
        Compliance_Requirement(
            Id="ac_2_5",
            Description="Account Management",
            Name="The information system automatically audits account creation, modification, enabling, disabling, and removal actions, and notifies [Assignment: organization-defined personnel or roles].",
            Attributes=[
                Generic_Compliance_Requirement_Attribute(
                    ItemId="ac_2_4",
                    Section="Access Control (AC)",
                    SubSection="Account Management (AC-2)",
                    Service="aws",
                )
            ],
            Checks=[],
        ),
    ],
)
KISA_ISMSP_AWS_NAME = "kisa_isms-p_2023_aws"
KISA_ISMSP_AWS = Compliance(
    Framework="KISA-ISMS-P",
    Provider="AWS",
    Version="2023",
    Description="The ISMS-P certification, established by KISA Korea Internet & Security Agency",
    Requirements=[
        Compliance_Requirement(
            Id="2.5.3",
            Name="User Authentication",
            Description="User access to information systems",
            Attributes=[
                KISA_ISMSP_Requirement_Attribute(
                    Domain="2. Protection Measure Requirements",
                    Subdomain="2.5. Authentication and Authorization Management",
                    Section="2.5.3 User Authentication",
                    AuditChecklist=[
                        "Is access to information systems and personal information controlled through secure authentication?",
                        "Are login attempt limitations enforced?",
                    ],
                    RelatedRegulations=[
                        "Personal Information Protection Act, Article 29",
                        "Standards for Ensuring the Safety of Personal Information, Article 5",
                    ],
                    AuditEvidence=[
                        "Login screen for information systems",
                        "Login failure message screen",
                    ],
                    NonComplianceCases=[
                        "Case 1: Insufficient authentication when accessing information systems externally.",
                        "Case 2: No limitation on login failure attempts.",
                    ],
                )
            ],
            Checks=[
                "cloudwatch_log_metric_filter_authentication_failures",
                "cognito_user_pool_mfa_enabled",
            ],
        ),
        Compliance_Requirement(
            Id="2.5.4",
            Name="User Authentication",
            Description="User access to information systems",
            Attributes=[
                KISA_ISMSP_Requirement_Attribute(
                    Domain="2. Protection Measure Requirements",
                    Subdomain="2.5. Authentication and Authorization Management",
                    Section="2.5.3 User Authentication",
                    AuditChecklist=[
                        "Is access to information systems and personal information controlled through secure authentication?",
                        "Are login attempt limitations enforced?",
                    ],
                    RelatedRegulations=[
                        "Personal Information Protection Act, Article 29",
                        "Standards for Ensuring the Safety of Personal Information, Article 5",
                    ],
                    AuditEvidence=[
                        "Login screen for information systems",
                        "Login failure message screen",
                    ],
                    NonComplianceCases=[
                        "Case 1: Insufficient authentication when accessing information systems externally.",
                        "Case 2: No limitation on login failure attempts.",
                    ],
                )
            ],
            Checks=[],
        ),
    ],
)
