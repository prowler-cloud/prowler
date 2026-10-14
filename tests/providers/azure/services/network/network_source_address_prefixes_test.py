from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule

from prowler.providers.azure.services.network.network_service import Network
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


@pytest.mark.parametrize(
    "service,port,protocol",
    [
        ("ssh", "22", "Tcp"),
        ("rdp", "3389", "Tcp"),
        ("http", "80", "Tcp"),
        ("udp", "53", "Udp"),
    ],
)
@pytest.mark.parametrize(
    "source,prefixes,access,direction,expected",
    [
        pytest.param(None, ["0.0.0.0/0"], "Allow", "Inbound", "FAIL", id="public-list"),
        pytest.param(
            None, ["10.0.0.0/8"], "Allow", "Inbound", "PASS", id="private-list"
        ),
        pytest.param(None, [], "Allow", "Inbound", "PASS", id="empty-list"),
        pytest.param(None, None, "Allow", "Inbound", "PASS", id="unset-list"),
        pytest.param(None, ["0.0.0.0/0"], "Deny", "Inbound", "PASS", id="deny-public"),
        pytest.param(
            None, ["0.0.0.0/0"], "Allow", "Outbound", "PASS", id="outbound-public"
        ),
        pytest.param(
            "Internet", None, "Allow", "Inbound", "FAIL", id="singular-internet"
        ),
        pytest.param("*", None, "Allow", "Inbound", "FAIL", id="singular-wildcard"),
        pytest.param(
            "0.0.0.0/0", None, "Allow", "Inbound", "FAIL", id="singular-public"
        ),
    ],
)
def test_internet_source_address_prefixes(
    service, port, protocol, source, prefixes, access, direction, expected
):
    """Internet sources in Azure's plural field must not be reported as safe."""
    sdk_rule = SecurityRule(
        id="rule-id",
        name="plural-source",
        destination_port_range=port,
        protocol=protocol,
        source_address_prefix=source,
        source_address_prefixes=prefixes,
        access=access,
        direction=direction,
    )
    sdk_group = NetworkSecurityGroup(
        location="westeurope",
        security_rules=[sdk_rule],
    )
    sdk_group.id = "group-id"
    sdk_group.name = "group-name"
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [sdk_group]
    network = Network.__new__(Network)
    network.clients = {AZURE_SUBSCRIPTION_ID: client}
    network.resource_groups = None
    network.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    network.security_groups = network._get_security_groups()
    stored_rule = network.security_groups[AZURE_SUBSCRIPTION_ID][0].security_rules[0]
    assert stored_rule.source_address_prefix == source
    assert stored_rule.source_address_prefixes == (prefixes or [])

    check_name = f"network_{service}_internet_access_restricted"
    module_name = f"prowler.providers.azure.services.network.{check_name}.{check_name}"
    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=MagicMock,
        ),
        patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=MagicMock,
        ),
    ):
        check_module = import_module(module_name)
        with patch.object(check_module, "network_client", network):
            results = getattr(check_module, check_name)().execute()

    assert len(results) == 1
    report = results[0]
    assert report.status == expected
    exposure = "allowed" if expected == "FAIL" else "restricted"
    assert report.status_extended == (
        f"Security Group group-name from subscription {AZURE_SUBSCRIPTION_DISPLAY} "
        f"has {service.upper()} internet access {exposure}."
    )
    assert report.subscription == AZURE_SUBSCRIPTION_ID
    assert report.resource_id == "group-id"
    assert report.resource_name == "group-name"
    assert report.location == "westeurope"
