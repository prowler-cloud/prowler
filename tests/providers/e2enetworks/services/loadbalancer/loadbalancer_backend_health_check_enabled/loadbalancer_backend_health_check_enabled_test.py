from unittest import mock

from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancer,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_backend_health_check_enabled.loadbalancer_backend_health_check_enabled.loadbalancer_client"


class Test_loadbalancer_backend_health_check_enabled:
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
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_backend_health_check_enabled.loadbalancer_backend_health_check_enabled import (
                loadbalancer_backend_health_check_enabled,
            )

            assert loadbalancer_backend_health_check_enabled().execute() == []

    def test_loadbalancer_backend_health_check_enabled_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(
                id="1",
                name="ok",
                location="Delhi",
                lb_mode="HTTP",
                backends=[{"http_check": True}],
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_backend_health_check_enabled.loadbalancer_backend_health_check_enabled import (
                loadbalancer_backend_health_check_enabled,
            )

            findings = loadbalancer_backend_health_check_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_loadbalancer_backend_health_check_enabled_non_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(
                id="2", name="bad", location="Delhi", lb_mode="HTTP", backends=[{}]
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_backend_health_check_enabled.loadbalancer_backend_health_check_enabled import (
                loadbalancer_backend_health_check_enabled,
            )

            findings = loadbalancer_backend_health_check_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
