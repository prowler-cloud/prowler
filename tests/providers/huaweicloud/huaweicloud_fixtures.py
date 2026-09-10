from unittest.mock import MagicMock

from prowler.providers.common.models import Audit_Metadata
from prowler.providers.huaweicloud.models import HuaweiCloudIdentityInfo


def set_mocked_huaweicloud_provider(
    account_id: str = "123456789012",
    account_name: str = "test-account",
    domain_id: str = "123456789012",
    user_id: str = "123456",
    user_name: str = "test-user",
    region: str = "la-south-2",
) -> MagicMock:
    """Create a mocked Huawei Cloud provider for service unit tests."""
    provider = MagicMock()
    provider.type = "huaweicloud"

    provider.identity = HuaweiCloudIdentityInfo(
        account_id=account_id,
        account_name=account_name,
        domain_id=domain_id,
        user_id=user_id,
        user_name=user_name,
        identity_type="user",
        regions={region},
        profile="default",
        profile_region=region,
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
