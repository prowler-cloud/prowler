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


class Test_ec2_instance_port_ssh_exposed_to_internet_fixer:
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
                    "ToPort": 25,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/24"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
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
                        "ToPort": 25,
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
                        "FromPort": 22,
                        "ToPort": 22,
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

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                    new=EC2(aws_provider),
                ),
            ):
                # Test Fixer
                from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
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
                    "FromPort": 22,
                    "ToPort": 22,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
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
                    "FromPort": 22,
                    "ToPort": 22,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance_id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_instance_exposed_port_in_public_subnet_only_22_port(self):
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
                    "FromPort": 22,
                    "ToPort": 22,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance.id, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_ec2_fixer_keeps_other_sources_of_the_rule(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")[
            "Subnet"
        ]["SubnetId"]
        bastion_sg_id = ec2_client.create_security_group(
            GroupName="bastion", Description="bastion", VpcId=vpc_id
        )["GroupId"]
        sg_id = ec2_client.create_security_group(
            GroupName="app", Description="app", VpcId=vpc_id
        )["GroupId"]
        prefix_list_id = ec2_client.create_managed_prefix_list(
            PrefixListName="corp",
            AddressFamily="IPv4",
            MaxEntries=5,
            Entries=[{"Cidr": "198.51.100.0/24"}],
        )["PrefixList"]["PrefixListId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}, {"CidrIpv6": "2001:db8::/32"}],
                    "PrefixListIds": [{"PrefixListId": prefix_list_id}],
                    "UserIdGroupPairs": [{"GroupId": bastion_sg_id}],
                }
            ],
        )
        instance_id = ec2_client.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
        )["Instances"][0]["InstanceId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.ec2.ec2_instance_port_ssh_exposed_to_internet.ec2_instance_port_ssh_exposed_to_internet_fixer import (
                fixer,
            )

            assert fixer(instance_id, AWS_REGION_EU_WEST_1)

        ingress_rules = ec2_client.describe_security_groups(GroupIds=[sg_id])[
            "SecurityGroups"
        ][0]["IpPermissions"]
        assert len(ingress_rules) == 1
        assert ingress_rules[0]["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]
        assert ingress_rules[0]["Ipv6Ranges"] == [{"CidrIpv6": "2001:db8::/32"}]
        assert [
            prefix_list["PrefixListId"]
            for prefix_list in ingress_rules[0]["PrefixListIds"]
        ] == [prefix_list_id]
        assert [
            group_pair["GroupId"] for group_pair in ingress_rules[0]["UserIdGroupPairs"]
        ] == [bastion_sg_id]
