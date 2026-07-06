from unittest import mock

from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancer,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)


class TestLoadBalancerBitninjaEnabledCheck:
    def test_pass_and_fail(self):
        loadbalancer_client = mock.MagicMock()
        loadbalancer_client.load_balancers = [
            LoadBalancer(
                id="1",
                name="protected-lb",
                location="Delhi",
                enable_bitninja=True,
            ),
            LoadBalancer(
                id="2",
                name="unprotected-lb",
                location="Delhi",
                enable_bitninja=False,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(
                "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled.loadbalancer_client",
                new=loadbalancer_client,
            ),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled import (
                loadbalancer_bitninja_enabled,
            )

            findings = loadbalancer_bitninja_enabled().execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[0].resource_id == "1"
            assert findings[1].status == "FAIL"
            assert findings[1].resource_id == "2"
