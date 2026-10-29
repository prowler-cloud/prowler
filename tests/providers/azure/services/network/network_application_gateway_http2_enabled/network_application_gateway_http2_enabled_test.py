from unittest import mock

from prowler.providers.azure.services.network.network_service import (
    ApplicationGateway,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "network_application_gateway_http2_enabled"
CHECK_PATH = f"prowler.providers.azure.services.network.{CHECK}.{CHECK}"
GATEWAY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/applicationGateways/agw1"
PREFIX = f"Application Gateway agw1 in subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def run_check(gateways, lookup_failed=()):
    network_client = mock.MagicMock()
    network_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    network_client.application_gateways = gateways
    network_client.application_gateways_lookup_failed = set(lookup_failed)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.network_client", new=network_client),
    ):
        from prowler.providers.azure.services.network.network_application_gateway_http2_enabled.network_application_gateway_http2_enabled import (
            network_application_gateway_http2_enabled,
        )

        return network_application_gateway_http2_enabled().execute()


def single(http2_enabled: bool):
    gateway = ApplicationGateway(
        id=GATEWAY_ID, name="agw1", location="westeurope", http2_enabled=http2_enabled
    )
    return run_check({AZURE_SUBSCRIPTION_ID: {GATEWAY_ID: gateway}})


UNLISTED = f"Cannot evaluate HTTP/2 on the Application Gateways in subscription {AZURE_SUBSCRIPTION_DISPLAY}: they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."


def assert_gateway_finding(finding, status, status_extended):
    assert finding.status == status
    assert finding.status_extended == status_extended
    assert finding.subscription == AZURE_SUBSCRIPTION_ID
    assert finding.resource_id == GATEWAY_ID
    assert finding.resource_name == "agw1"
    assert finding.location == "westeurope"


def assert_subscription_finding(finding):
    assert finding.status == "MANUAL"
    assert finding.status_extended == UNLISTED
    assert finding.subscription == AZURE_SUBSCRIPTION_ID
    assert finding.resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
    assert finding.resource_name == AZURE_SUBSCRIPTION_ID
    assert finding.location == "global"


class Test_network_application_gateway_http2_enabled:
    def test_no_gateways(self):
        assert run_check({}) == []
        assert run_check({AZURE_SUBSCRIPTION_ID: {}}) == []

    def test_http2_enabled(self):
        result = single(True)
        assert len(result) == 1
        assert_gateway_finding(result[0], "PASS", f"{PREFIX} has HTTP/2 enabled.")

    def test_http2_disabled(self):
        result = single(False)
        assert len(result) == 1
        assert_gateway_finding(
            result[0], "FAIL", f"{PREFIX} does not have HTTP/2 enabled."
        )

    def test_gateways_lookup_failed_is_manual(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {}}, lookup_failed={AZURE_SUBSCRIPTION_ID}
        )
        assert len(result) == 1
        assert_subscription_finding(result[0])

    def test_partial_lookup_still_reports_listed_gateways(self):
        gateway = ApplicationGateway(
            id=GATEWAY_ID, name="agw1", location="westeurope", http2_enabled=True
        )
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {GATEWAY_ID: gateway}},
            lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 2
        assert_subscription_finding(result[0])
        assert_gateway_finding(result[1], "PASS", f"{PREFIX} has HTTP/2 enabled.")
