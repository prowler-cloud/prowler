from unittest.mock import MagicMock

from prowler.providers.alibabacloud.models import AlibabaCloudIdentityInfo
from prowler.providers.common.models import Audit_Metadata


def set_mocked_alibabacloud_provider(
    account_id: str = "1234567890",
    account_name: str = "test-account",
    user_id: str = "123456",
    user_name: str = "test-user",
    region: str = "cn-hangzhou",
) -> MagicMock:
    """Create a mocked Alibaba Cloud provider for service unit tests."""
    provider = MagicMock()
    provider.type = "alibabacloud"

    provider.identity = AlibabaCloudIdentityInfo(
        account_id=account_id,
        account_name=account_name,
        user_id=user_id,
        user_name=user_name,
        identity_arn=f"acs:ram::{account_id}:user/{user_name}",
        profile="default",
        profile_region=region,
        audited_regions={region},
        is_root=False,
    )

    provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=[],
        completed_checks=0,
        audit_progress=0,
    )
    provider.audit_resources = []
    provider.audit_config = {}
    provider.fixer_config = {}
    provider.mutelist = MagicMock()
    provider.mutelist.is_muted = MagicMock(return_value=False)

    # Session/client mocks
    provider.session = MagicMock()
    provider.session.client = MagicMock(return_value=MagicMock(region=region))

    # Region helpers
    provider.get_default_region = MagicMock(return_value=region)

    def mock_generate_regional_clients(service_name):
        return {region: MagicMock(region=region)}

    provider.generate_regional_clients = MagicMock(
        side_effect=mock_generate_regional_clients
    )

    return provider
