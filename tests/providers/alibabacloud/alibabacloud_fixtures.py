from mock import MagicMock

from prowler.providers.alibabacloud.alibabacloud_provider import AlibabacloudProvider
from prowler.providers.alibabacloud.models import (
    AlibabaCloudCredentials,
    AlibabaCloudIdentityInfo,
    AlibabaCloudSession,
)

ALIBABACLOUD_ACCOUNT_ID = "LTAI5tGKAbeoSf7Mddg9"
ALIBABACLOUD_ACCOUNT_ARN = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:root"
ALIBABACLOUD_REGION = "cn-hangzhou"


def set_mocked_alibabacloud_provider(
    account_id: str = ALIBABACLOUD_ACCOUNT_ID,
    account_arn: str = ALIBABACLOUD_ACCOUNT_ARN,
    access_key_id: str = "LTAI5tGKAbeoSf7Mddg9",
    access_key_secret: str = "mock_secret",
    region: str = ALIBABACLOUD_REGION,
    audit_config: dict = None,
) -> AlibabacloudProvider:
    """
    Create a mocked Alibaba Cloud provider for testing

    Args:
        account_id: Alibaba Cloud account ID
        account_arn: Alibaba Cloud account ARN
        access_key_id: Access key ID
        access_key_secret: Access key secret
        region: Default region
        audit_config: Audit configuration

    Returns:
        Mocked AlibabacloudProvider instance
    """
    provider = MagicMock()
    provider.type = "alibabacloud"

    # Set up credentials
    credentials = AlibabaCloudCredentials(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
    )

    # Set up session
    session = AlibabaCloudSession(
        credentials=credentials,
        region_id=region,
    )
    provider.session = session

    # Set up identity
    identity = AlibabaCloudIdentityInfo(
        account_id=account_id,
        account_arn=account_arn,
    )
    provider.identity = identity

    # Set audit config
    provider.audit_config = audit_config if audit_config else {}

    return provider
