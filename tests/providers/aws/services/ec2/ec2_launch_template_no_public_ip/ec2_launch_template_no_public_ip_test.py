from os import path
from pathlib import Path
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 1,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": False}],
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 2,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": True}],
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v3(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 3,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [
                            {
                                "AssociatePublicIpAddress": True,
                                "NetworkInterfaceId": "eni-1234567890",
                            }
                        ],
                    },
                },
                {
                    "VersionNumber": 4,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [
                            {"NetworkInterfaceId": "eni-1234567890"},
                            {"AssociatePublicIpAddress": True},
                        ],
                    },
                },
                {
                    "VersionNumber": 5,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": False}],
                    },
                },
            ]
        }
    elif operation_name == "DescribeNetworkInterfaces":
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1234567890",
                    "SubnetId": "subnet-6789abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.175.48.10",
                    "InterfaceType": "interface",
                    "PrivateDnsName": "ip-192-175-48-10.ec2.internal",
                    "PrivateIpAddresses": [
                        {
                            "PrivateIpAddress": "192.175.48.10",
                            "Primary": True,
                        }
                    ],
                    "Ipv6Addresses": [{"Ipv6Address": "2001:db8:abcd:0012::10"}],
                    "Association": {
                        "PublicIp": "203.0.113.5",
                        "PublicDnsName": "ec2-203-0-113-5.compute-1.amazonaws.com",
                        "IpOwnerId": "amazon",
                    },
                    "TagSet": [{"Key": "string", "Value": "string"}],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v4(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 6,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [
                            {
                                "AssociatePublicIpAddress": True,
                                "NetworkInterfaceId": "eni-1234567890",
                            }
                        ],
                    },
                },
                {
                    "VersionNumber": 7,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1234567890"}],
                    },
                },
            ]
        }
    elif operation_name == "DescribeNetworkInterfaces":
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1234567890",
                    "SubnetId": "subnet-6789abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "10.0.0.10",
                    "InterfaceType": "interface",
                    "PrivateDnsName": "ip-10-0-0-10.ec2.internal",
                    "PrivateIpAddresses": [
                        {
                            "PrivateIpAddress": "10.0.0.10",
                            "Primary": True,
                        }
                    ],
                    "Ipv6Addresses": [{"Ipv6Address": "2001:20:abcd:0012::10"}],
                    "Association": {
                        "PublicIp": "10.0.0.10",
                        "PublicDnsName": "ec2-203-0-113-5.compute-1.amazonaws.com",
                        "IpOwnerId": "amazon",
                    },
                    "TagSet": [{"Key": "string", "Value": "string"}],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_launch_template_no_public_ip:
    @mock_aws
    def test_no_launch_templates(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.launch_templates = []

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_launch_template_no_public_ip(self):
        # Include launch_template to check
        launch_template_name = "test-no-public-ip"
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with no public IP",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        launch_template_id = ec2_client.describe_launch_templates(
            LaunchTemplateNames=[launch_template_name]
        )["LaunchTemplates"][0]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EC2 Launch Template {launch_template_name} is neither configured to assign a public IP address to network interfaces upon launch nor using a network interface with public IP addresses."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_launch_template_public_ip_auto_assign(self):
        # Include launch_template to check
        launch_template_name = "test-public-ip-auto-assign"
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with public IP auto-assign",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        launch_template_id = ec2_client.describe_launch_templates(
            LaunchTemplateNames=[launch_template_name]
        )["LaunchTemplates"][0]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "EC2 Launch Template test-public-ip-auto-assign is configured to assign a public IP address to network interfaces upon launch in template versions: 2."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v3)
    def test_network_interface_with_public_ipv4_network_interface_autoassign_true_and_false(
        self,
    ):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        # Include launch_template to check
        launch_template_name = "test-eni-public-ip4-and-auto-assign"
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with public IP auto-assign",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        # Retrieve the Launch Template ID
        launch_template_id = ec2_client.describe_launch_templates(
            LaunchTemplateNames=[launch_template_name]
        )["LaunchTemplates"][0]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EC2 Launch Template {launch_template_name} is configured to assign a public IP address to network interfaces upon launch in template versions: 3, 4 and is using a network interface with public IP addresses in template versions: 3, 4."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v4)
    def test_network_interface_with_public_ipv6_network_interface_autoassign_true_and_false(
        self,
    ):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        # Include launch_template to check
        launch_template_name = "test-eni-public-ip6-and-auto-assign"
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with public IP auto-assign",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        # Retrieve the Launch Template ID
        launch_template_id = ec2_client.describe_launch_templates(
            LaunchTemplateNames=[launch_template_name]
        )["LaunchTemplates"][0]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EC2 Launch Template {launch_template_name} is configured to assign a public IP address to network interfaces upon launch in template versions: 6 and is using a network interface with public IP addresses in template versions: 6, 7."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
