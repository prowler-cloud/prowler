import os

from botocore.config import Config

AWS_STS_GLOBAL_ENDPOINT_REGION = "us-east-1"
AWS_REGION_US_EAST_1 = "us-east-1"
BOTO3_USER_AGENT_EXTRA = os.getenv("PROWLER_AWS_BOTO3_USER_AGENT_EXTRA", "APN_1826889")
ROLE_SESSION_NAME = "ProwlerAssessmentSession"

# Bootstrap candidates per partition, used when no session region is configured.
PARTITION_BOOTSTRAP_REGIONS = {
    "aws-cn": ("cn-north-1", "cn-northwest-1"),
    "aws-eusc": ("eusc-de-east-1",),
    "aws-us-gov": ("us-gov-east-1", "us-gov-west-1"),
}


def get_default_session_config() -> Config:
    return Config(
        user_agent_extra=BOTO3_USER_AGENT_EXTRA,
        retries={"max_attempts": 3, "mode": "standard"},
    )
