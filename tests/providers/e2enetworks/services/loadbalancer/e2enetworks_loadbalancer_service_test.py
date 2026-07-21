from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service import (
    LoadBalancers,
)


class TestLoadBalancerService:
    @patch(
        "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service.E2eNetworksService.__init__"
    )
    def test_fetch_loadbalancers_parses_context(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = LoadBalancers.__new__(LoadBalancers)
        service.provider = provider
        service.client = MagicMock()
        service.load_balancers = []

        service.client.paginate.return_value = [
            {
                "id": 42,
                "name": "web-alb",
                "status": "running",
                "node_detail": {"public_ip": "164.52.2.2"},
                "appliance_instance": [
                    {
                        "context": {
                            "lb_mode": "HTTPS",
                            "lb_port": 443,
                            "enable_bitninja": True,
                            "ssl_context": {"ssl_certificate_id": 7},
                            "backends": [{"http_check": True}],
                        }
                    }
                ],
            }
        ]

        service._fetch_loadbalancers()

        assert len(service.load_balancers) == 1
        lb = service.load_balancers[0]
        assert lb.id == "42"
        assert lb.name == "web-alb"
        assert lb.location == "Delhi"
        assert lb.lb_mode == "HTTPS"
        assert lb.enable_bitninja is True
        assert lb.ssl_certificate_id == "7"
        assert lb.public_ip == "164.52.2.2"
        assert lb.is_alb is True
        assert lb.is_alb_https is True
        assert lb.has_backend_health_check is True

    @patch(
        "prowler.providers.e2enetworks.services.loadbalancer.loadbalancer_service.E2eNetworksService.__init__"
    )
    def test_fetch_loadbalancers_handles_missing_context(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = LoadBalancers.__new__(LoadBalancers)
        service.provider = provider
        service.client = MagicMock()
        service.load_balancers = []

        service.client.paginate.return_value = [
            {"id": 1, "name": "tcp-lb", "status": "running"}
        ]

        service._fetch_loadbalancers()

        assert len(service.load_balancers) == 1
        lb = service.load_balancers[0]
        assert lb.enable_bitninja is False
        assert lb.ssl_certificate_id is None
        assert lb.is_alb is False
        assert lb.has_backend_health_check is False
