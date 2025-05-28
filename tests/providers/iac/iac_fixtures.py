# IAC Provider Constants
DEFAULT_SCAN_PATH = "."
DEFAULT_REGION = "global"
DEFAULT_ACCOUNT = "local-iac"
DEFAULT_IDENTITY = "prowler"

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
