from unittest import mock

import botocore
from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLoadBalancerAttributes":
        if kwarg["LoadBalancerName"] == "my-lb-strictest":
            return {
                "LoadBalancerAttributes": {
                    "CrossZoneLoadBalancing": {"Enabled": True},
                    "AccessLog": {
                        "Enabled": False,
                        "EmitInterval": 60,
                    },
                    "ConnectionDraining": {"Enabled": False, "Timeout": 300},
                    "ConnectionSettings": {
                        "IdleTimeout": 60,
                    },
                    "AdditionalAttributes": [
                        {
                            "Key": "elb.http.desyncmitigationmode",
                            "Value": "strictest",
                        }
                    ],
                }
            }
        if kwarg["LoadBalancerName"] == "my-lb-defensive":
            return {
                "LoadBalancerAttributes": {
                    "CrossZoneLoadBalancing": {"Enabled": True},
                    "AccessLog": {
                        "Enabled": False,
                        "EmitInterval": 60,
                    },
                    "ConnectionDraining": {"Enabled": False, "Timeout": 300},
                    "ConnectionSettings": {
                        "IdleTimeout": 60,
                    },
                    "AdditionalAttributes": [
                        {
                            "Key": "elb.http.desyncmitigationmode",
                            "Value": "defensive",
                        }
                    ],
                }
            }
        if kwarg["LoadBalancerName"] == "my-lb-monitor":
            return {
                "LoadBalancerAttributes": {
                    "CrossZoneLoadBalancing": {"Enabled": True},
                    "AccessLog": {
                        "Enabled": False,
                        "EmitInterval": 60,
                    },
                    "ConnectionDraining": {"Enabled": False, "Timeout": 300},
                    "ConnectionSettings": {
                        "IdleTimeout": 60,
                    },
                    "AdditionalAttributes": [
                        {
                            "Key": "elb.http.desyncmitigationmode",
                            "Value": "monitor",
                        }
                    ],
                }
            }

    return make_api_call(self, operation_name, kwarg)


class Test_elb_desync_mitigation_mode:
    @mock_aws
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.elb.elb_service import ELB

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode import (
                elb_desync_mitigation_mode,
            )

            check = elb_desync_mitigation_mode()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_elb_with_monitor_desync_mode(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb-monitor",
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
            "prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode import (
                elb_desync_mitigation_mode,
            )

            check = elb_desync_mitigation_mode()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELB my-lb-monitor has desync mitigation mode set to monitor, not to strictest or defensive."
            )
            assert result[0].resource_id == "my-lb-monitor"
            assert (
                result[0].resource_arn
                == "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/my-lb-monitor"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_elb_with_defensive_desync_mode(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb-defensive",
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
            "prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode import (
                elb_desync_mitigation_mode,
            )

            check = elb_desync_mitigation_mode()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb-defensive has desync mitigation mode set to defensive."
            )
            assert result[0].resource_id == "my-lb-defensive"
            assert (
                result[0].resource_arn
                == "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/my-lb-defensive"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_elb_with_strictest_desync_mode(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb-strictest",
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
            "prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode.elb_client",
            new=ELB(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            from prowler.providers.aws.services.elb.elb_desync_mitigation_mode.elb_desync_mitigation_mode import (
                elb_desync_mitigation_mode,
            )

            check = elb_desync_mitigation_mode()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb-strictest has desync mitigation mode set to strictest."
            )
            assert result[0].resource_id == "my-lb-strictest"
            assert (
                result[0].resource_arn
                == "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/my-lb-strictest"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
