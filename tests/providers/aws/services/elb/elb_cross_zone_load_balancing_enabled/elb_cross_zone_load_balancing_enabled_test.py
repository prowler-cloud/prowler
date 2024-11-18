from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_elb_cross_zone_load_balancing_enabled:
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners.elb_ssl_listeners.elb_client",
            new=ELB(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_ssl_listeners.elb_ssl_listeners import (
                elb_ssl_listeners,
            )

            check = elb_ssl_listeners()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_default_elb(self):
        elb_client = client("elb", region_name=AWS_REGION_EU_WEST_1)
        # Create a compliant resource
        elb_client.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            Scheme="internet-facing",
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled.elb_client",
            new=ELB(aws_provider),
        ):
            from prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled import (
                elb_cross_zone_load_balancing_enabled,
            )

            check = elb_cross_zone_load_balancing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert (
                result[0].status == "FAIL"
            )  # This should be a PASS, because AWS by default enables cross-zone load balancing but moto doesn't
            assert (
                result[0].status_extended
                == "ELB my-lb does not have cross-zone load balancing enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "my-lb"
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_elb_with_cross_zone_lb_enabled(self):
        elb_client = client("elb", region_name=AWS_REGION_EU_WEST_1)
        # Create a compliant resource
        elb_client.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            Scheme="internet-facing",
        )

        elb_client.modify_load_balancer_attributes(
            LoadBalancerName="my-lb",
            LoadBalancerAttributes={
                "CrossZoneLoadBalancing": {"Enabled": True},
            },
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled.elb_client",
            new=ELB(aws_provider),
        ):
            from prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled import (
                elb_cross_zone_load_balancing_enabled,
            )

            check = elb_cross_zone_load_balancing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb has cross-zone load balancing enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "my-lb"
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_elb_with_cross_zone_lb_disabled(self):
        elb_client = client("elb", region_name=AWS_REGION_EU_WEST_1)
        # Create a non-compliant resource
        elb_client.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            Scheme="internet-facing",
        )

        elb_client.modify_load_balancer_attributes(
            LoadBalancerName="my-lb",
            LoadBalancerAttributes={
                "CrossZoneLoadBalancing": {"Enabled": False},
            },
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled.elb_client",
            new=ELB(aws_provider),
        ):
            from prowler.providers.aws.services.elb.elb_cross_zone_load_balancing_enabled.elb_cross_zone_load_balancing_enabled import (
                elb_cross_zone_load_balancing_enabled,
            )

            check = elb_cross_zone_load_balancing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELB my-lb does not have cross-zone load balancing enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "my-lb"
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
            )
            assert result[0].resource_tags == []
