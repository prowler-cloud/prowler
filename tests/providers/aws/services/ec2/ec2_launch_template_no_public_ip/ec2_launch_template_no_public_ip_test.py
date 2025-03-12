from base64 import b64encode
from ipaddress import IPv4Address, IPv6Address
from os import path
from pathlib import Path
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.config.config import encoding_format_utf_8
from prowler.providers.aws.services.ec2.ec2_service import (
    Attachment,
    LaunchTemplate,
    LaunchTemplateVersion,
    NetworkInterface,
    TemplateData,
)
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
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    def test_launch_template_public_ip_auto_assign(self):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        launch_template_data = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=True,
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=2,
                template_data=launch_template_data,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=ec2_client,
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
                == f"EC2 Launch Template {launch_template_name} is configured to assign a public IP address to network interfaces upon launch in template versions: 2."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    def test_network_interface_with_public_ipv4_network_interface_autoassign_true_and_false(
        self,
    ):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        network_interface = NetworkInterface(
            id="eni-1234567890",
            association={},
            attachment=Attachment(),
            private_ip="",
            public_ip_addresses=[IPv4Address("192.175.48.10")],
            type="interface",
            subnet_id="subnet-1234567890",
            vpc_id="vpc-1234567890",
            region=AWS_REGION_US_EAST_1,
        )

        launch_template_data = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=False,
            network_interfaces=[network_interface],
        )
        launch_template_data2 = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=True,
            network_interfaces=[network_interface],
        )
        launch_template_data3 = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=False,
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=3,
                template_data=launch_template_data,
            ),
            LaunchTemplateVersion(
                version_number=4,
                template_data=launch_template_data2,
            ),
            LaunchTemplateVersion(
                version_number=5,
                template_data=launch_template_data3,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=ec2_client,
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
                == f"EC2 Launch Template {launch_template_name} is configured to assign a public IP address to network interfaces upon launch in template versions: 4 and is using a network interface with public IP addresses in template versions: 3, 4."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    def test_network_interface_with_public_ipv6_network_interface_autoassign_true_and_false(
        self,
    ):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        network_interface = NetworkInterface(
            id="eni-1234567890",
            association={},
            attachment=Attachment(),
            private_ip="",
            public_ip_addresses=[IPv6Address("::1234:5678")],
            type="interface",
            subnet_id="subnet-1234567890",
            vpc_id="vpc-1234567890",
            region=AWS_REGION_US_EAST_1,
        )

        launch_template_data = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=True,
            network_interfaces=[network_interface],
        )
        launch_template_data2 = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=False,
            network_interfaces=[network_interface],
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=6,
                template_data=launch_template_data,
            ),
            LaunchTemplateVersion(
                version_number=7,
                template_data=launch_template_data2,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip.ec2_client",
            new=ec2_client,
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
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []
