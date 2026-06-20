from unittest import mock

from prowler.providers.e2e.services.network.network_service import Vpc
from tests.providers.e2e.e2e_fixtures import set_mocked_e2e_provider


class TestNetworkVpcIsActiveCheck:
    def test_pass_and_fail(self):
        network_client = mock.MagicMock()
        network_client.vpcs = [
            Vpc(
                network_id="1",
                name="active-vpc",
                location="Delhi",
                is_active=True,
                state="Active",
            ),
            Vpc(
                network_id="2",
                name="inactive-vpc",
                location="Delhi",
                is_active=False,
                state="Inactive",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2e_provider(),
            ),
            mock.patch(
                "prowler.providers.e2e.services.network.network_vpc_is_active.network_vpc_is_active.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.e2e.services.network.network_vpc_is_active.network_vpc_is_active import (
                network_vpc_is_active,
            )

            findings = network_vpc_is_active().execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[1].status == "FAIL"
