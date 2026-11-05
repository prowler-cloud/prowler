from unittest import mock

from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancer,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled.loadbalancer_client"


class Test_loadbalancer_bitninja_enabled:
    def test_no_load_balancers(self):
        client = mock.MagicMock()
        client.load_balancers = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled import (
                loadbalancer_bitninja_enabled,
            )

            assert loadbalancer_bitninja_enabled().execute() == []

    def test_loadbalancer_bitninja_enabled_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(id="1", name="ok", location="Delhi", enable_bitninja=True),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled import (
                loadbalancer_bitninja_enabled,
            )

            findings = loadbalancer_bitninja_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_loadbalancer_bitninja_enabled_non_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(id="2", name="bad", location="Delhi", enable_bitninja=False),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_bitninja_enabled.loadbalancer_bitninja_enabled import (
                loadbalancer_bitninja_enabled,
            )

            findings = loadbalancer_bitninja_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
