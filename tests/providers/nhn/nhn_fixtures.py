from mock import MagicMock
from prowler.providers.nhn.nhn_provider import NhnProvider

def set_mocked_nhn_provider(
    username="test_user",
    password="test_password",
    tenant_id="tenant123",
    audit_config=None,
    fixer_config=None
):
    """
    Creates a mocked NHN Provider object for testing without real network calls.
    """
    provider = MagicMock(spec=NhnProvider)  # or just MagicMock()

    provider.type = "nhn"
    provider._username = username
    provider._password = password
    provider._tenant_id = tenant_id
    provider._token = "fake_keystone_token"

    provider.session = MagicMock()

    provider.audit_config = audit_config
    provider.fixer_config = fixer_config

    return provider
