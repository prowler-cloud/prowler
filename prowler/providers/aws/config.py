import os

from botocore.config import Config

from prowler.providers.aws.exceptions.exceptions import AWSInvalidBoto3TimeoutError

AWS_STS_GLOBAL_ENDPOINT_REGION = "us-east-1"
AWS_REGION_US_EAST_1 = "us-east-1"
BOTO3_USER_AGENT_EXTRA = os.getenv("PROWLER_AWS_BOTO3_USER_AGENT_EXTRA", "APN_1826889")
BOTO3_RETRIES_MAX_ATTEMPTS = 3
# botocore defaults both to 60s
BOTO3_CONNECT_TIMEOUT = 10
BOTO3_READ_TIMEOUT = 60
ROLE_SESSION_NAME = "ProwlerAssessmentSession"


def get_boto3_timeout_from_env(name: str, default: int) -> int:
    """Positive integer seconds read from the environment, or default when unset."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    if not raw.isdecimal() or int(raw) == 0:
        raise AWSInvalidBoto3TimeoutError(
            file=os.path.basename(__file__),
            message=f"{name} must be a positive integer number of seconds, got {raw!r}",
        )
    return int(raw)


def get_default_session_config() -> Config:
    return Config(
        user_agent_extra=BOTO3_USER_AGENT_EXTRA,
        retries={"max_attempts": BOTO3_RETRIES_MAX_ATTEMPTS, "mode": "standard"},
        connect_timeout=get_boto3_timeout_from_env(
            "PROWLER_AWS_BOTO3_CONNECT_TIMEOUT", BOTO3_CONNECT_TIMEOUT
        ),
        read_timeout=get_boto3_timeout_from_env(
            "PROWLER_AWS_BOTO3_READ_TIMEOUT", BOTO3_READ_TIMEOUT
        ),
    )
