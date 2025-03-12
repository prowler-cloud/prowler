from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    set_mocked_aws_provider,
)


class Test_elb_is_in_multiple_az:
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az.elb_client",
            new=ELB(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az import (
                elb_is_in_multiple_az,
            )

            check = elb_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elbv2_in_one_avaibility_zone(self):
        elb_client = client("elb", region_name=AWS_REGION_EU_WEST_1)
        # Create a compliant resource

        elb_client.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internet-facing",
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az.elb_client",
            new=ELB(aws_provider),
        ):
            from prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az import (
                elb_is_in_multiple_az,
            )

            check = elb_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Classic Load Balancer my-lb is not in at least 2 availability zones, it is only in {AWS_REGION_EU_WEST_1_AZA}."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "my-lb"
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
            )
            assert result[0].resource_tags == []

    @mock_aws
    def test_elbv2_in_multiple_avaibility_zones(self):
        elb_client = client("elb", region_name=AWS_REGION_EU_WEST_1)
        # Create a compliant resource

        elb_client.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA, AWS_REGION_EU_WEST_1_AZB],
            Scheme="internet-facing",
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az.elb_client",
            new=ELB(aws_provider),
        ):
            from prowler.providers.aws.services.elb.elb_is_in_multiple_az.elb_is_in_multiple_az import (
                elb_is_in_multiple_az,
            )

            check = elb_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Classic Load Balancer my-lb is in 2 availability zones: {AWS_REGION_EU_WEST_1_AZA}, {AWS_REGION_EU_WEST_1_AZB}."
            ) or (
                result[0].status_extended
                == f"Classic Load Balancer my-lb is in 2 availability zones: {AWS_REGION_EU_WEST_1_AZB}, {AWS_REGION_EU_WEST_1_AZA}."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "my-lb"
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticloadbalancing:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
            )
            assert result[0].resource_tags == []
