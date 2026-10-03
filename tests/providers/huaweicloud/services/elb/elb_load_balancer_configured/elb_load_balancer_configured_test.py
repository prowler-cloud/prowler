from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestElbLoadBalancerConfigured:
    def test_load_balancer_exists_passes(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured import (
                elb_load_balancer_configured,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import (
                LoadBalancer,
            )

            lb = LoadBalancer(
                id="lb-1",
                name="my-lb",
                vip_address="192.168.1.1",
                public_ip="",
                is_public=False,
                region="la-south-2",
            )
            elb_client.load_balancers = [lb]
            elb_client.audited_account = "123456789012"
            elb_client.region = "la-south-2"

            check = elb_load_balancer_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "configured" in result[0].status_extended

    def test_multiple_load_balancers_pass(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured import (
                elb_load_balancer_configured,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import (
                LoadBalancer,
            )

            lb1 = LoadBalancer(
                id="lb-1",
                name="lb-1",
                vip_address="192.168.1.1",
                public_ip="",
                is_public=False,
                region="la-south-2",
            )
            lb2 = LoadBalancer(
                id="lb-2",
                name="lb-2",
                vip_address="192.168.1.2",
                public_ip="",
                is_public=False,
                region="la-south-2",
            )
            elb_client.load_balancers = [lb1, lb2]
            elb_client.audited_account = "123456789012"
            elb_client.region = "la-south-2"

            check = elb_load_balancer_configured()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "PASS"

    def test_no_load_balancers_fails(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_load_balancer_configured.elb_load_balancer_configured import (
                elb_load_balancer_configured,
            )

            elb_client.load_balancers = []
            elb_client.audited_account = "123456789012"
            elb_client.region = "la-south-2"

            check = elb_load_balancer_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No ELB load balancers" in result[0].status_extended
