from unittest import mock

import botocore
import botocore.client
from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_error(self, operation_name, kwarg):
    if operation_name == "RevokeSecurityGroupIngress":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "InvalidPermission.NotFound",
                    "Message": "The specified rule does not exist in this security group.",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_ec2_instance_port_mysql_exposed_to_internet_fixer:
    @mock_aws
    def test_ec2_instance_exposed_port_in_private_subnet_with_ip4_and_ip6(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 1,
                    "ToPort": 4000,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/24"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/24"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}],
                },
            ],
        )
        subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")[
            "Subnet"
        ]["SubnetId"]
        instance_id = ec2_resource.create_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SecurityGroupIds=[default_sg_id],
            SubnetId=subnet_id,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "test"}]}
            ],
        )[0].id

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance_id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_instance_exposed_port_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_error
        ):
            # Create EC2 Mocked Resources
            ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
            ec2_resource = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
            vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
            default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
                "SecurityGroups"
            ][0]
            default_sg_id = default_sg["GroupId"]
            ec2_client.authorize_security_group_ingress(
                GroupId=default_sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 1,
                        "ToPort": 4000,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"},
                            {"CidrIp": "10.0.0.0/24"},
                        ],
                        "Ipv6Ranges": [
                            {"CidrIpv6": "::/0"},
                            {"CidrIpv6": "2001:db8::/32"},
                        ],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3306,
                        "ToPort": 3306,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"},
                            {"CidrIp": "10.0.0.0/24"},
                        ],
                        "Ipv6Ranges": [
                            {"CidrIpv6": "::/0"},
                            {"CidrIpv6": "2001:db8::/32"},
                        ],
                    },
                ],
            )
            subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")[
                "Subnet"
            ]["SubnetId"]
            instance_id = ec2_resource.create_instances(
                ImageId="ami-12345678",
                MinCount=1,
                MaxCount=1,
                InstanceType="t2.micro",
                SecurityGroupIds=[default_sg_id],
                SubnetId=subnet_id,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": "test"}],
                    }
                ],
            )[0].id

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer import (
                    fixer,
                )

                assert not fixer(instance_id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_instance_exposed_port_in_private_subnet_only_with_ip4(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/24"}],
                },
            ],
        )
        subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")[
            "Subnet"
        ]["SubnetId"]
        instance_id = ec2_resource.create_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SecurityGroupIds=[default_sg_id],
            SubnetId=subnet_id,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "test"}]}
            ],
        )[0].id

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance_id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_instance_exposed_port_in_private_subnet_only_with_ip6(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}],
                },
            ],
        )
        subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")[
            "Subnet"
        ]["SubnetId"]
        instance_id = ec2_resource.create_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SecurityGroupIds=[default_sg_id],
            SubnetId=subnet_id,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "test"}]}
            ],
        )[0].id

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance_id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_instance_exposed_port_in_public_subnet_only_3306_port(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")[
            "Subnet"
        ]["SubnetId"]
        instance = ec2_resource.create_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SecurityGroupIds=[default_sg_id],
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet_id,
                    "AssociatePublicIpAddress": True,
                }
            ],
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "test"}]}
            ],
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_mysql_exposed_to_internet.ec2_instance_port_mysql_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance.id, AWS_REGION_EU_WEST_1)
