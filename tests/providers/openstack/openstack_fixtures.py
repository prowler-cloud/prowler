"""OpenStack provider test fixtures."""

from unittest.mock import MagicMock

from prowler.providers.openstack.models import OpenStackIdentityInfo, OpenStackSession
from prowler.providers.openstack.openstack_provider import OpenstackProvider

OPENSTACK_AUTH_URL = "https://openstack.example.com:5000/v3"
OPENSTACK_USERNAME = "test-user"
OPENSTACK_PROJECT_ID = "test-project-id"
OPENSTACK_PROJECT_NAME = "test-project"
OPENSTACK_REGION = "RegionOne"
OPENSTACK_USER_ID = "test-user-id"
OPENSTACK_DOMAIN = "Default"


def set_mocked_openstack_provider(
    auth_url: str = OPENSTACK_AUTH_URL,
    username: str = OPENSTACK_USERNAME,
    project_id: str = OPENSTACK_PROJECT_ID,
    region_name: str = OPENSTACK_REGION,
    audit_config: dict = None,
) -> OpenstackProvider:
    """Create a mocked OpenStack provider for testing.

    Args:
        auth_url: OpenStack authentication URL
        username: OpenStack username
        project_id: OpenStack project ID
        region_name: OpenStack region name
        audit_config: Optional audit configuration

    Returns:
        Mocked OpenstackProvider instance
    """
    provider = MagicMock(spec=OpenstackProvider)
    provider.type = "openstack"

    # Mock session
    provider.session = OpenStackSession(
        auth_url=auth_url,
        identity_api_version="3",
        username=username,
        password="test-password",
        project_id=project_id,
        region_name=region_name,
        user_domain_name=OPENSTACK_DOMAIN,
        project_domain_name=OPENSTACK_DOMAIN,
    )

    # Mock identity
    provider.identity = OpenStackIdentityInfo(
        user_id=OPENSTACK_USER_ID,
        username=username,
        project_id=project_id,
        project_name=OPENSTACK_PROJECT_NAME,
        region_name=region_name,
        user_domain_name=OPENSTACK_DOMAIN,
        project_domain_name=OPENSTACK_DOMAIN,
    )

    # Mock connection
    provider.connection = MagicMock()

    # Mock regional connections (single-region default)
    provider.regional_connections = {region_name: provider.connection}

    # Mock audit config
    provider.audit_config = audit_config or {}
    provider.fixer_config = {}

    return provider
