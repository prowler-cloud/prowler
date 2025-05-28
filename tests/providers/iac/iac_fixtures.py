from mock import MagicMock

from prowler.providers.common.models import Audit_Metadata
from prowler.providers.iac.iac_provider import IacProvider

# IAC Provider Constants
DEFAULT_SCAN_PATH = "."
DEFAULT_REGION = "global"
DEFAULT_ACCOUNT = "local-iac"
DEFAULT_IDENTITY = "prowler"

# Sample Checkov Output
SAMPLE_CHECKOV_OUTPUT = [
    {
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
SAMPLE_FINDING = {"results": SAMPLE_CHECKOV_OUTPUT[0]["results"]}

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

# Sample Config Content
SAMPLE_CONFIG_CONTENT = {
    "custom_setting": "value",
    "threshold": 100,
    "enable_feature": True,
}

SAMPLE_FIXER_CONFIG = {"fix_setting": "enabled", "auto_fix": False}


def set_mocked_iac_provider(
    scan_path: str = DEFAULT_SCAN_PATH,
    config_content: dict = None,
    fixer_config: dict = None,
    audit_metadata: Audit_Metadata = None,
) -> IacProvider:
    """
    Create a mocked IAC provider for testing.

    Args:
        scan_path: The directory path to scan
        config_content: Custom audit configuration
        fixer_config: Custom fixer configuration
        audit_metadata: Custom audit metadata

    Returns:
        MagicMock: Mocked IAC provider instance
    """
    provider = MagicMock()
    provider.type = "iac"
    provider._type = "iac"
    provider.scan_path = scan_path
    provider.region = DEFAULT_REGION
    provider.audited_account = DEFAULT_ACCOUNT
    provider.identity = DEFAULT_IDENTITY
    provider.session = None
    provider._audit_config = config_content or {}
    provider._fixer_config = fixer_config or {}
    provider._mutelist = None

    if audit_metadata:
        provider.audit_metadata = audit_metadata
    else:
        provider.audit_metadata = Audit_Metadata(
            provider="iac",
            account_id=DEFAULT_ACCOUNT,
            account_name="iac",
            region=DEFAULT_REGION,
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

    return provider


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
