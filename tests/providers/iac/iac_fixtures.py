# IAC Provider Constants
DEFAULT_SCAN_PATH = "."

# Sample Checkov Output
SAMPLE_CHECKOV_OUTPUT = [
    {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_name": "Ensure S3 bucket has encryption enabled",
                    "guideline": "https://docs.bridgecrew.io/docs/s3_1-s3-bucket-has-encryption-enabled",
                    "severity": "low",
                },
                {
                    "check_id": "CKV_AWS_2",
                    "check_name": "Ensure S3 bucket has public access blocked",
                    "guideline": "https://docs.bridgecrew.io/docs/s3_2-s3-bucket-has-public-access-blocked",
                    "severity": "low",
                },
            ],
            "passed_checks": [
                {
                    "check_id": "CKV_AWS_3",
                    "check_name": "Ensure S3 bucket has versioning enabled",
                    "guideline": "https://docs.bridgecrew.io/docs/s3_3-s3-bucket-has-versioning-enabled",
                    "severity": "low",
                }
            ],
        },
    }
]

# Sample Finding Data
SAMPLE_FINDING = SAMPLE_CHECKOV_OUTPUT[0]

SAMPLE_FAILED_CHECK = {
    "check_id": "CKV_AWS_1",
    "check_name": "Ensure S3 bucket has encryption enabled",
    "guideline": "https://docs.bridgecrew.io/docs/s3_1-s3-bucket-has-encryption-enabled",
    "severity": "low",
}

SAMPLE_PASSED_CHECK = {
    "check_id": "CKV_AWS_3",
    "check_name": "Ensure S3 bucket has versioning enabled",
    "guideline": "https://docs.bridgecrew.io/docs/s3_3-s3-bucket-has-versioning-enabled",
    "severity": "low",
}

# Additional sample checks
SAMPLE_ANOTHER_FAILED_CHECK = {
    "check_id": "CKV_AWS_4",
    "check_name": "Ensure S3 bucket has logging enabled",
    "guideline": "https://docs.bridgecrew.io/docs/s3_4-s3-bucket-has-logging-enabled",
    "severity": "medium",
}

SAMPLE_ANOTHER_PASSED_CHECK = {
    "check_id": "CKV_AWS_5",
    "check_name": "Ensure S3 bucket has lifecycle policy",
    "guideline": "https://docs.bridgecrew.io/docs/s3_5-s3-bucket-has-lifecycle-policy",
    "severity": "low",
}

SAMPLE_ANOTHER_SKIPPED_CHECK = {
    "check_id": "CKV_AWS_6",
    "check_name": "Ensure S3 bucket has object lock enabled",
    "guideline": "https://docs.bridgecrew.io/docs/s3_6-s3-bucket-has-object-lock-enabled",
    "severity": "high",
    "suppress_comment": "Not applicable for this use case",
}

SAMPLE_SKIPPED_CHECK = {
    "check_id": "CKV_AWS_7",
    "check_name": "Ensure S3 bucket has server-side encryption",
    "guideline": "https://docs.bridgecrew.io/docs/s3_7-s3-bucket-has-server-side-encryption",
    "severity": "medium",
    "suppress_comment": "Legacy bucket, will be migrated",
}

SAMPLE_HIGH_SEVERITY_CHECK = {
    "check_id": "CKV_AWS_8",
    "check_name": "Ensure S3 bucket has public access blocked",
    "guideline": "https://docs.bridgecrew.io/docs/s3_8-s3-bucket-has-public-access-blocked",
    "severity": "high",
}

# Dockerfile samples
SAMPLE_DOCKERFILE_REPORT = {
    "check_type": "dockerfile",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_DOCKER_1",
                "check_name": "Ensure base image is not using latest tag",
                "guideline": "https://docs.bridgecrew.io/docs/docker_1-base-image-not-using-latest-tag",
                "severity": "medium",
            }
        ],
        "passed_checks": [],
    },
}

SAMPLE_DOCKERFILE_CHECK = {
    "check_id": "CKV_DOCKER_1",
    "check_name": "Ensure base image is not using latest tag",
    "guideline": "https://docs.bridgecrew.io/docs/docker_1-base-image-not-using-latest-tag",
    "severity": "medium",
}

# YAML samples
SAMPLE_YAML_REPORT = {
    "check_type": "yaml",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_K8S_1",
                "check_name": "Ensure API server is not exposed",
                "guideline": "https://docs.bridgecrew.io/docs/k8s_1-api-server-not-exposed",
                "severity": "high",
            }
        ],
        "passed_checks": [],
    },
}

SAMPLE_YAML_CHECK = {
    "check_id": "CKV_K8S_1",
    "check_name": "Ensure API server is not exposed",
    "guideline": "https://docs.bridgecrew.io/docs/k8s_1-api-server-not-exposed",
    "severity": "high",
}

# CloudFormation samples
SAMPLE_CLOUDFORMATION_CHECK = {
    "check_id": "CKV_AWS_9",
    "check_name": "Ensure CloudFormation stack has drift detection enabled",
    "guideline": "https://docs.bridgecrew.io/docs/aws_9-cloudformation-stack-has-drift-detection-enabled",
    "severity": "low",
}

# Kubernetes samples
SAMPLE_KUBERNETES_CHECK = {
    "check_id": "CKV_K8S_2",
    "check_name": "Ensure RBAC is enabled",
    "guideline": "https://docs.bridgecrew.io/docs/k8s_2-rbac-enabled",
    "severity": "medium",
}


def get_sample_checkov_json_output():
    """Return sample Checkov JSON output as string"""
    import json

    return json.dumps(SAMPLE_CHECKOV_OUTPUT)


def get_empty_checkov_output():
    """Return empty Checkov output as string"""
    return "[]"


def get_invalid_checkov_output():
    """Return invalid JSON output as string"""
    return "invalid json output"
