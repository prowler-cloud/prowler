# IAC Provider Constants
DEFAULT_SCAN_PATH = "."

# Sample Trivy Output
SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "main.tf",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0001",
                    "Title": "S3 bucket should have encryption enabled",
                    "Description": "S3 bucket should have encryption enabled",
                    "Message": "S3 bucket should have encryption enabled",
                    "Resolution": "Enable encryption on the S3 bucket",
                    "Severity": "LOW",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0001",
                    "RuleID": "AVD-AWS-0001",
                },
                {
                    "ID": "AVD-AWS-0002",
                    "Title": "S3 bucket should have public access blocked",
                    "Description": "S3 bucket should have public access blocked",
                    "Message": "S3 bucket should have public access blocked",
                    "Resolution": "Block public access on the S3 bucket",
                    "Severity": "LOW",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0002",
                    "RuleID": "AVD-AWS-0002",
                },
            ],
            "Vulnerabilities": [],
            "Secrets": [],
            "Licenses": [],
        },
        {
            "Target": "main.tf",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0003",
                    "Title": "S3 bucket should have versioning enabled",
                    "Description": "S3 bucket should have versioning enabled",
                    "Message": "S3 bucket should have versioning enabled",
                    "Resolution": "Enable versioning on the S3 bucket",
                    "Severity": "LOW",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0003",
                    "RuleID": "AVD-AWS-0003",
                }
            ],
            "Vulnerabilities": [],
            "Secrets": [],
            "Licenses": [],
        },
    ]
}

# Sample Finding Data
SAMPLE_FINDING = SAMPLE_TRIVY_OUTPUT["Results"][0]

SAMPLE_FAILED_CHECK = {
    "ID": "AVD-AWS-0001",
    "Title": "S3 bucket should have encryption enabled",
    "Description": "S3 bucket should have encryption enabled",
    "Message": "S3 bucket should have encryption enabled",
    "Resolution": "Enable encryption on the S3 bucket",
    "Severity": "low",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0001",
    "RuleID": "AVD-AWS-0001",
}

SAMPLE_PASSED_CHECK = {
    "ID": "AVD-AWS-0003",
    "Title": "S3 bucket should have versioning enabled",
    "Description": "S3 bucket should have versioning enabled",
    "Message": "S3 bucket should have versioning enabled",
    "Resolution": "Enable versioning on the S3 bucket",
    "Severity": "low",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0003",
    "RuleID": "AVD-AWS-0003",
}

# Additional sample checks
SAMPLE_ANOTHER_FAILED_CHECK = {
    "ID": "AVD-AWS-0004",
    "Title": "S3 bucket should have logging enabled",
    "Description": "S3 bucket should have logging enabled",
    "Message": "S3 bucket should have logging enabled",
    "Resolution": "Enable logging on the S3 bucket",
    "Severity": "medium",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0004",
    "RuleID": "AVD-AWS-0004",
}

SAMPLE_ANOTHER_PASSED_CHECK = {
    "ID": "AVD-AWS-0005",
    "Title": "S3 bucket should have lifecycle policy",
    "Description": "S3 bucket should have lifecycle policy",
    "Message": "S3 bucket should have lifecycle policy",
    "Resolution": "Configure lifecycle policy on the S3 bucket",
    "Severity": "low",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0005",
    "RuleID": "AVD-AWS-0005",
}

SAMPLE_ANOTHER_SKIPPED_CHECK = {
    "ID": "AVD-AWS-0006",
    "Title": "S3 bucket should have object lock enabled",
    "Description": "S3 bucket should have object lock enabled",
    "Message": "S3 bucket should have object lock enabled",
    "Resolution": "Enable object lock on the S3 bucket",
    "Severity": "high",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0006",
    "RuleID": "AVD-AWS-0006",
    "Status": "MUTED",
}

SAMPLE_SKIPPED_CHECK = {
    "ID": "AVD-AWS-0007",
    "Title": "S3 bucket should have server-side encryption",
    "Description": "S3 bucket should have server-side encryption",
    "Message": "S3 bucket should have server-side encryption",
    "Resolution": "Enable server-side encryption on the S3 bucket",
    "Severity": "medium",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0007",
    "RuleID": "AVD-AWS-0007",
    "Status": "MUTED",
}

SAMPLE_HIGH_SEVERITY_CHECK = {
    "ID": "AVD-AWS-0008",
    "Title": "S3 bucket should have public access blocked",
    "Description": "S3 bucket should have public access blocked",
    "Message": "S3 bucket should have public access blocked",
    "Resolution": "Block public access on the S3 bucket",
    "Severity": "high",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3/avd-aws-0008",
    "RuleID": "AVD-AWS-0008",
}

# Dockerfile samples
SAMPLE_DOCKERFILE_REPORT = {
    "Target": "Dockerfile",
    "Type": "dockerfile",
    "Misconfigurations": [
        {
            "ID": "AVD-DOCKER-0001",
            "Title": "Base image should not use latest tag",
            "Description": "Base image should not use latest tag",
            "Message": "Base image should not use latest tag",
            "Resolution": "Use a specific version tag instead of latest",
            "Severity": "medium",
            "PrimaryURL": "https://avd.aquasec.com/misconfig/docker/dockerfile/avd-docker-0001",
            "RuleID": "AVD-DOCKER-0001",
        }
    ],
    "Vulnerabilities": [],
    "Secrets": [],
    "Licenses": [],
}

SAMPLE_DOCKERFILE_CHECK = {
    "ID": "AVD-DOCKER-0001",
    "Title": "Base image should not use latest tag",
    "Description": "Base image should not use latest tag",
    "Message": "Base image should not use latest tag",
    "Resolution": "Use a specific version tag instead of latest",
    "Severity": "medium",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/docker/dockerfile/avd-docker-0001",
    "RuleID": "AVD-DOCKER-0001",
}

# YAML samples
SAMPLE_YAML_REPORT = {
    "Target": "deployment.yaml",
    "Type": "kubernetes",
    "Misconfigurations": [
        {
            "ID": "AVD-K8S-0001",
            "Title": "API server should not be exposed",
            "Description": "API server should not be exposed",
            "Message": "API server should not be exposed",
            "Resolution": "Do not expose the API server",
            "Severity": "high",
            "PrimaryURL": "https://avd.aquasec.com/misconfig/kubernetes/avd-k8s-0001",
            "RuleID": "AVD-K8S-0001",
        }
    ],
    "Vulnerabilities": [],
    "Secrets": [],
    "Licenses": [],
}

SAMPLE_YAML_CHECK = {
    "ID": "AVD-K8S-0001",
    "Title": "API server should not be exposed",
    "Description": "API server should not be exposed",
    "Message": "API server should not be exposed",
    "Resolution": "Do not expose the API server",
    "Severity": "high",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/kubernetes/avd-k8s-0001",
    "RuleID": "AVD-K8S-0001",
}

# CloudFormation samples
SAMPLE_CLOUDFORMATION_CHECK = {
    "ID": "AVD-AWS-0009",
    "Title": "CloudFormation stack should have drift detection enabled",
    "Description": "CloudFormation stack should have drift detection enabled",
    "Message": "CloudFormation stack should have drift detection enabled",
    "Resolution": "Enable drift detection on the CloudFormation stack",
    "Severity": "low",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/cloudformation/avd-aws-0009",
    "RuleID": "AVD-AWS-0009",
}

# Kubernetes samples
SAMPLE_KUBERNETES_CHECK = {
    "ID": "AVD-K8S-0002",
    "Title": "RBAC should be enabled",
    "Description": "RBAC should be enabled",
    "Message": "RBAC should be enabled",
    "Resolution": "Enable RBAC on the cluster",
    "Severity": "medium",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/kubernetes/avd-k8s-0002",
    "RuleID": "AVD-K8S-0002",
}

# Sample Trivy output with vulnerabilities
SAMPLE_TRIVY_VULNERABILITY_OUTPUT = {
    "Results": [
        {
            "Target": "package.json",
            "Type": "nodejs",
            "Misconfigurations": [],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "Title": "Example vulnerability",
                    "Description": "This is an example vulnerability",
                    "Severity": "high",
                    "PrimaryURL": "https://example.com/cve-2023-1234",
                }
            ],
            "Secrets": [],
            "Licenses": [],
        }
    ]
}

# Sample Trivy output with secrets
SAMPLE_TRIVY_SECRET_OUTPUT = {
    "Results": [
        {
            "Target": "config.yaml",
            "Class": "secret",
            "Misconfigurations": [],
            "Vulnerabilities": [],
            "Secrets": [
                {
                    "ID": "aws-access-key-id",
                    "Title": "AWS Access Key ID",
                    "Description": "AWS Access Key ID found in configuration",
                    "Severity": "critical",
                    "PrimaryURL": "https://example.com/secret-aws-access-key-id",
                }
            ],
            "Licenses": [],
        }
    ]
}


def get_sample_trivy_json_output():
    """Return sample Trivy JSON output as string"""
    import json

    return json.dumps(SAMPLE_TRIVY_OUTPUT)


def get_empty_trivy_output():
    """Return empty Trivy output as string"""
    import json

    return json.dumps({"Results": []})


def get_invalid_trivy_output():
    """Return invalid JSON output as string"""
    return "invalid json output"
