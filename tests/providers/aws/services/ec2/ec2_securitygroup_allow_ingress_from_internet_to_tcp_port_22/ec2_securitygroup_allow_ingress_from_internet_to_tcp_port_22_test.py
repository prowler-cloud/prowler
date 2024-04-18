from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.vpc.vpc_service import VPC
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22:
    @mock_aws
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # All are compliant by default
            assert result[0].status == "PASS"
            assert result[1].status == "PASS"
            assert result[2].status == "PASS"

    @mock_aws
    def test_ec2_non_compliant_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]
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

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has SSH port 22 open to the Internet but it is not attached."
                    )
                    assert search(
                        "has SSH port 22 open to the Internet",
                        sg.status_extended,
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.check_metadata.Severity == "medium"
                    assert sg.resource_tags == []

    @mock_aws
    def test_ec2_compliant_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) does not have SSH port 22 open to the Internet."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_aws
    def test_ec2_default_sgs_ignoring(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            scan_unused_services=False,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_default_sgs_ignoring_vpc_in_use(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        ec2.create_network_interface(SubnetId=subnet.id)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg["GroupId"]
        default_sg["GroupName"]
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            scan_unused_services=False,
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_sg_attached_to_instance_with_private_ip(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        network_interface = ec2.create_network_interface(SubnetId=subnet.id)

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
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
        # Attach instance to default sg
        instance_id = ec2.create_instances(
            NetworkInterfaces=[
                {
                    "NetworkInterfaceId": network_interface.id,
                    "DeviceIndex": 0,
                }
            ],
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[default_sg_id],
        )[0].id

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 2
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"EC2 Instance {instance_id} has SSH exposed to 0.0.0.0/0 on private ip address {network_interface.private_ip_address}."
                    )
                    assert sg.check_metadata.Severity == "high"

    @mock_aws
    def test_ec2_sg_attached_to_instance_with_public_ip(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        network_interface = ec2.create_network_interface(SubnetId=subnet.id)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Associate public ip to network interface
        ec2_client.associate_address(
            AllocationId=ec2_client.allocate_address(Domain="vpc")["AllocationId"],
            NetworkInterfaceId=network_interface.id,
        )
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
        # Attach instance to default sg
        instance_id = ec2.create_instances(
            NetworkInterfaces=[
                {
                    "NetworkInterfaceId": network_interface.id,
                    "DeviceIndex": 0,
                    "AssociatePublicIpAddress": True,
                }
            ],
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[default_sg_id],
        )[0].id
        # Get Instance public ip
        public_ip = ec2_client.describe_instances(InstanceIds=[instance_id])[
            "Reservations"
        ][0]["Instances"][0]["PublicIpAddress"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 2
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"EC2 Instance {instance_id} has SSH exposed to 0.0.0.0/0 on public ip address {public_ip}."
                    )
                    assert sg.check_metadata.Severity == "high"

    @mock_aws
    def test_ec2_sg_attached_to_instance_with_public_ip_in_public_subnet(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        network_interface = ec2.create_network_interface(SubnetId=subnet.id)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create IGW and attach to VPC
        igw = ec2.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)
        # Set IGW as default route for public subnet
        route_table = ec2.create_route_table(VpcId=vpc.id)
        route_table.associate_with_subnet(SubnetId=subnet.id)
        ec2_client.create_route(
            RouteTableId=route_table.id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw.id,
        )
        # Associate public ip to network interface
        ec2_client.associate_address(
            AllocationId=ec2_client.allocate_address(Domain="vpc")["AllocationId"],
            NetworkInterfaceId=network_interface.id,
        )
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
        # Attach instance to default sg
        instance_id = ec2.create_instances(
            NetworkInterfaces=[
                {
                    "NetworkInterfaceId": network_interface.id,
                    "DeviceIndex": 0,
                    "AssociatePublicIpAddress": True,
                }
            ],
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[default_sg_id],
        )[0].id
        # Get Instance public ip
        public_ip = ec2_client.describe_instances(InstanceIds=[instance_id])[
            "Reservations"
        ][0]["Instances"][0]["PublicIpAddress"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22()
            result = check.execute()

            # One default sg per region
            assert len(result) == 2
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"EC2 Instance {instance_id} has SSH exposed to 0.0.0.0/0 on public ip address {public_ip} within public subnet {subnet.id}."
                    )
                    assert sg.check_metadata.Severity == "critical"
