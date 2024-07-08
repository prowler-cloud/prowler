from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    Compliance_Requirement,
    ComplianceBaseModel,
)

CIS_1_4_AWS_NAME = "cis_1.4_aws"
CIS_1_4_AWS = ComplianceBaseModel(
    Framework="CIS",
    Provider="AWS",
    Version="1.4",
    Description="The CIS Benchmark for CIS Amazon Web Services Foundations Benchmark, v1.4.0, Level 1 and 2 provides prescriptive guidance for configuring security options for a subset of Amazon Web Services. It has an emphasis on foundational, testable, and architecture agnostic settings",
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
CIS_2_0_AZURE_NAME = "cis_2.0_azure"
CIS_2_0_AZURE = ComplianceBaseModel(
    Framework="CIS",
    Provider="Azure",
    Version="2.0",
    Description="The CIS Azure Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Azure with an emphasis on foundational, testable, and architecture agnostic settings.",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
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
        )
    ],
)
CIS_2_0_GCP_NAME = "cis_2.0_gcp"
CIS_2_0_GCP = ComplianceBaseModel(
    Framework="CIS",
    Provider="GCP",
    Version="2.0",
    Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
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
        )
    ],
)
CIS_1_8_KUBERNETES_NAME = "cis_2.0_kubernetes"
CIS_1_8_KUBERNETES = ComplianceBaseModel(
    Framework="CIS",
    Provider="Kubernetes",
    Version="1.8",
    Description="This CIS Kubernetes Benchmark provides prescriptive guidance for establishing a secure configuration posture for Kubernetes v1.27.",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
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
        )
    ],
)
CIS_1_5_AWS_NAME = "cis_1.5_aws"
CIS_1_5_AWS = ComplianceBaseModel(
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

NOT_PRESENT_COMPLIANCE_NAME = "not_present_compliance_name"
NOT_PRESENT_COMPLIANCE = ComplianceBaseModel(
    Framework="NOT_EXISTENT",
    Provider="NOT_EXISTENT",
    Version="NOT_EXISTENT",
    Description="NOT_EXISTENT",
    Requirements=[],
)
