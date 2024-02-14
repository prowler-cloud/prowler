from unittest.mock import patch

from prowler.providers.azure.services.network.network_service import (
    Network,
    SecurityGroup,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_sqlserver_get_security_groups(_):
    return {
        AZURE_SUBSCRIPTION: [
            SecurityGroup(
                id="id",
                name="name",
                location="location",
                security_rules=[],
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.network.network_service.Network.__get_security_groups__",
    new=mock_sqlserver_get_security_groups,
)
class Test_Network_Service:
    def test__get_client__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "NetworkManagementClient"
        )

    def test__get_security_groups__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "SecurityGroup"
        )
        assert network.security_groups[AZURE_SUBSCRIPTION][0].id == "id"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].name == "name"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].location == "location"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].security_rules == []
