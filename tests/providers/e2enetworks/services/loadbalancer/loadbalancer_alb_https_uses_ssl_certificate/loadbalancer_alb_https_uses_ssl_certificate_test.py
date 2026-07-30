from unittest import mock

from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancer,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_alb_https_uses_ssl_certificate.loadbalancer_alb_https_uses_ssl_certificate.loadbalancer_client"


class Test_loadbalancer_alb_https_uses_ssl_certificate:
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
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_alb_https_uses_ssl_certificate.loadbalancer_alb_https_uses_ssl_certificate import (
                loadbalancer_alb_https_uses_ssl_certificate,
            )

            assert loadbalancer_alb_https_uses_ssl_certificate().execute() == []

    def test_loadbalancer_alb_https_uses_ssl_certificate_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(
                id="1",
                name="ok",
                location="Delhi",
                lb_mode="HTTPS",
                ssl_certificate_id="cert-1",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_alb_https_uses_ssl_certificate.loadbalancer_alb_https_uses_ssl_certificate import (
                loadbalancer_alb_https_uses_ssl_certificate,
            )

            findings = loadbalancer_alb_https_uses_ssl_certificate().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_loadbalancer_alb_https_uses_ssl_certificate_non_compliant(self):
        client = mock.MagicMock()
        client.load_balancers = [
            LoadBalancer(
                id="2",
                name="bad",
                location="Delhi",
                lb_mode="HTTPS",
                ssl_certificate_id=None,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_alb_https_uses_ssl_certificate.loadbalancer_alb_https_uses_ssl_certificate import (
                loadbalancer_alb_https_uses_ssl_certificate,
            )

            findings = loadbalancer_alb_https_uses_ssl_certificate().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
