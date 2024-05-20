from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
elb_arn = (
    f"arn:aws:elasticloadbalancing:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
)


class Test_elb_logging_enabled:
    @mock_aws
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled import (
                elb_logging_enabled,
            )

            check = elb_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elb_without_access_log(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled import (
                elb_logging_enabled,
            )

            check = elb_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELB my-lb does not have access logs configured."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn

    @mock_aws
    def test_elb_with_deletion_protection(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        elb.modify_load_balancer_attributes(
            LoadBalancerName="my-lb",
            LoadBalancerAttributes={
                "AccessLog": {
                    "Enabled": True,
                    "S3BucketName": "mb",
                    "EmitInterval": 42,
                    "S3BucketPrefix": "s3bf",
                }
            },
        )

        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elb.elb_logging_enabled.elb_logging_enabled import (
                elb_logging_enabled,
            )

            check = elb_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb has access logs to S3 configured."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn
