from mock import MagicMock
from prowler.providers.ionos.ionos_provider import IonosProvider
from prowler.providers.ionos.models import IonosIdentityInfo
from prowler.providers.ionos.lib.mutelist.mutelist import IonosMutelist


def set_mocked_ionos_provider(
    username: str = "test_user",
    password: str = "test_password",
    datacenter_name: str = "test-datacenter",
    token: str = None,
    audit_config: dict = None,
    mutelist_content: dict = None,
):
    """
    Creates a mocked IONOS Provider object for testing without real network calls.
    """
    provider = MagicMock(spec=IonosProvider)

    provider.type = "ionos"
    provider._username = username
    provider._password = password
    provider._token = token
    provider._datacenter_name = datacenter_name

    # Mock API client session
    provider._session = MagicMock()
    provider._session.configuration = MagicMock()
    provider._session.configuration.username = username
    provider._session.configuration.password = password
    provider._session.configuration.host = "api.ionos.com"

    # Mock identity info
    provider._identity = IonosIdentityInfo(
        username=username,
        password=password,
        datacenter_id="datacenter123",  # This will be set after get_datacenter_id
        token=token,
    )

    # Mock configuration
    provider._audit_config = audit_config or {}
    provider._mutelist = IonosMutelist(mutelist_content=mutelist_content or {})

    # Mock basic provider methods
    provider.test_connection.return_value = True
    mock_datacenter = MagicMock()
    mock_datacenter.id = "datacenter123"
    mock_datacenter.properties.name = datacenter_name
    mock_datacenter.properties.location = "us/las"
    provider.get_datacenters.return_value = [mock_datacenter]
    
    # Mock property getters
    provider.identity = property(lambda self: self._identity)
    provider.session = property(lambda self: self._session)
    provider.audit_config = property(lambda self: self._audit_config)
    provider.mutelist = property(lambda self: self._mutelist)
    provider.type = property(lambda self: "ionos")

    return provider