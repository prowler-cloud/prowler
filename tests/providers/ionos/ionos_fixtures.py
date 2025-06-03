from mock import MagicMock
from prowler.providers.ionos.ionos_provider import IonosProvider
from prowler.providers.ionos.models import IonosIdentityInfo


def set_mocked_ionos_provider(
    username: str = "test_user",
    password: str = "test_password",
    datacenter_id: str = "datacenter123",
    token: str = "fake_token",
    audit_config: dict = None,
    fixer_config: dict = None,
):
    """
    Creates a mocked IONOS Provider object for testing without real network calls.
    """
    provider = MagicMock(spec=IonosProvider)

    provider.type = "ionos"
    provider._username = username
    provider._password = password
    provider._datacenter_id = datacenter_id
    provider._token = token

    provider.session = MagicMock()
    provider.session.configuration = MagicMock()
    provider.session.configuration.username = username
    provider.session.configuration.password = password
    provider.session.configuration.token = token
    provider.session.configuration.host = "api.ionos.com"

    provider._identity = IonosIdentityInfo(
        username=username,
        password=password,
        datacenter_id=datacenter_id,
        token=token,
    )

    provider.audit_config = audit_config
    provider.fixer_config = fixer_config

    # Mock basic provider methods
    provider.test_connection.return_value = True
    provider.get_datacenters.return_value = [
        MagicMock(
            id=datacenter_id,
            properties=MagicMock(
                name="Test Datacenter",
                location="us/las",
            ),
        )
    ]

    return provider