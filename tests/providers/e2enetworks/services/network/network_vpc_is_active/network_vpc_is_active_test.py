from unittest import mock

from prowler.providers.e2enetworks.services.network.network_service import (
    Vpc,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.network.network_vpc_is_active.network_vpc_is_active.network_client"


class Test_network_vpc_is_active:
    def test_no_vpcs(self):
        client = mock.MagicMock()
        client.vpcs = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_is_active.network_vpc_is_active import (
                network_vpc_is_active,
            )

            assert network_vpc_is_active().execute() == []

    def test_network_vpc_is_active_compliant(self):
        client = mock.MagicMock()
        client.vpcs = [
            Vpc(
                network_id="1",
                name="ok",
                location="Delhi",
                is_active=True,
                state="Active",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_is_active.network_vpc_is_active import (
                network_vpc_is_active,
            )

            findings = network_vpc_is_active().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_network_vpc_is_active_non_compliant(self):
        client = mock.MagicMock()
        client.vpcs = [
            Vpc(
                network_id="2",
                name="bad",
                location="Delhi",
                is_active=False,
                state="Inactive",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.network.network_vpc_is_active.network_vpc_is_active import (
                network_vpc_is_active,
            )

            findings = network_vpc_is_active().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
