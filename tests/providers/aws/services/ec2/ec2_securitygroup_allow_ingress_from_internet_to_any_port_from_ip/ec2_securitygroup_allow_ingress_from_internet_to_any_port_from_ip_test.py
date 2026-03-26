from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip"


class Test_ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip:
    @mock_aws
    def test_ec2_default_sgs(self):
        """Default SGs with no custom rules should PASS."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            # One default sg per region (2 regions) + 1 extra from create_vpc
            assert len(result) == 3
            assert all(sg.status == "PASS" for sg in result)

    @mock_aws
    def test_sg_with_specific_public_ip_ingress(self):
        """SG with a specific public IP (not 0.0.0.0/0) open to all protocols should FAIL."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Add a specific public IP ingress rule (all protocols)
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "52.94.76.5/32"}],
                }
            ],
        )

        # Create Network Interface to make the SG in-use
        ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[default_sg_id],
            Description="Test ENI",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has a port open to a specific public IP address in ingress rule."
                    )
                    assert sg.resource_details == default_sg_name

    @mock_aws
    def test_sg_with_private_ip_ingress(self):
        """SG with a private (RFC1918) IP ingress should PASS."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]

        # Add a private IP ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            assert len(result) == 3
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"

    @mock_aws
    def test_sg_with_specific_port_public_ip(self):
        """SG with a specific public IP on a specific port (not all protocols) should FAIL."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Add a specific public IP on a specific port
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "FromPort": 8080,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "52.94.76.10/32"}],
                    "Ipv6Ranges": [],
                    "ToPort": 8080,
                }
            ],
        )

        # Create Network Interface
        ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[default_sg_id],
            Description="Test ENI",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has a port open to a specific public IP address in ingress rule."
                    )

    @mock_aws
    def test_sg_pass_when_all_ports_already_failed(self):
        """SG already flagged by the all_ports check should PASS with explanation."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Add 0.0.0.0/0 all protocols (triggers all_ports check)
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_client",
                new=EC2(aws_provider),
            ) as ec2_mock,
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            # Run all_ports check first to set the failed flag
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
            )

            check_all = ec2_securitygroup_allow_ingress_from_internet_to_all_ports()
            result_all = check_all.execute()

            # Verify the all_ports check flagged it
            assert any(
                sg.status == "FAIL" and sg.resource_id == default_sg_id
                for sg in result_all
            )

            # Now run our check with the same ec2_client (which has the failed flags)
            with (
                mock.patch(
                    f"{CHECK_MODULE}.ec2_client",
                    new=ec2_mock,
                ),
                mock.patch(
                    f"{CHECK_MODULE}.vpc_client",
                    new=VPC(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                    ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
                )

                check = (
                    ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
                )
                result = check.execute()

                # The SG with 0.0.0.0/0 should PASS with explanation
                for sg in result:
                    if sg.resource_id == default_sg_id:
                        assert sg.status == "PASS"
                        assert (
                            sg.status_extended
                            == f"Security group {default_sg_name} ({default_sg_id}) has all ports open to the Internet and therefore was not checked against specific public IP ingress rules."
                        )

    @mock_aws
    def test_ec2_default_sgs_ignoring_unused(self):
        """Unused SGs should be skipped when scan_unused_services is False."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            scan_unused_services=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_sg_with_wildcard_cidr_on_specific_port(self):
        """SG with 0.0.0.0/0 on a specific port should PASS (covered by other checks)."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]

        # Add 0.0.0.0/0 on a specific port
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "FromPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "ToPort": 443,
                }
            ],
        )

        # Create Network Interface
        ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[default_sg_id],
            Description="Test ENI",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"

    @mock_aws
    def test_sg_with_ipv6_public_address(self):
        """SG with a specific public IPv6 address should FAIL."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Add a public IPv6 ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "2600:1f18::/32"}],
                }
            ],
        )

        # Create Network Interface
        ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[default_sg_id],
            Description="Test ENI",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE}.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                f"{CHECK_MODULE}.vpc_client",
                new=VPC(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip.ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip()
            result = check.execute()

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has a port open to a specific public IP address in ingress rule."
                    )
