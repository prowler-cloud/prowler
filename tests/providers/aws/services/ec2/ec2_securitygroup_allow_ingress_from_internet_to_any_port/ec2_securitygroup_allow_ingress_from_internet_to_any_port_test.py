from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.ec2.ec2_service import Attachment
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_securitygroup_allow_ingress_from_internet_to_any_port:
    @mock_aws
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        # Create Subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]

        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Authorize ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Create Network Interface
        network_interface_response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[
                default_sg_id
            ],  # Associating the network interface with the default security group
            Description="Test Network Interface",
        )

        self.verify_check_fail(
            default_sg_id, default_sg_name, network_interface_response
        )

    def verify_check_fail(
        self, default_sg_id, default_sg_name, network_interface_response
    ):
        eni = network_interface_response.get("NetworkInterface", {})
        eni_type = eni.get("InterfaceType", "")
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) has at least one port open to the Internet but its network interface type ({eni_type}) is not allowed."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_aws
    def test_check_enis(self):

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            audit_config={
                "ec2_allowed_interface_types": ["api_gateway_managed", "vpc_endpoint"],
                "ec2_allowed_instance_owners": ["amazon-elb"],
            },
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ):
            from unittest.mock import Mock

            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )
            from prowler.providers.aws.services.ec2.ec2_service import NetworkInterface

            tests = [
                {
                    "eni_interface_type": "vpc_endpoint",
                    "eni_instance_owner": "NOT_ALLOWED",
                    "report": {
                        "status": "PASS",
                        "status_extended": "Security group SG_name (SG_id) has at least one port open to the Internet and it is attached to an allowed network interface type (vpc_endpoint).",
                    },
                },
                {
                    "eni_interface_type": "NOT_ALLOWED",
                    "eni_instance_owner": "amazon-elb",
                    "report": {
                        "status": "PASS",
                        "status_extended": "Security group SG_name (SG_id) has at least one port open to the Internet and it is attached to an allowed network interface instance owner (amazon-elb).",
                    },
                },
                {
                    "eni_interface_type": "NOT_ALLOWED_ENI_TYPE",
                    "eni_instance_owner": "NOT_ALLOWED_INSTANCE_OWNER",
                    "report": {
                        "status": "FAIL",
                        "status_extended": "Security group SG_name (SG_id) has at least one port open to the Internet but its network interface type (NOT_ALLOWED_ENI_TYPE) is not allowed.",
                    },
                },
            ]

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()

            for test in tests:
                eni = NetworkInterface(
                    id="1",
                    association={},
                    attachment=Attachment(instance_owner_id=test["eni_instance_owner"]),
                    private_ip="1",
                    public_ip_addresses=[],
                    type=test["eni_interface_type"],
                    subnet_id="1",
                    vpc_id="1",
                    region="1",
                )

                report = Mock()
                check.check_enis(
                    report=report,
                    security_group_name="SG_name",
                    security_group_id="SG_id",
                    enis=[eni],
                )
                assert report.status == test["report"]["status"]
                assert report.status_extended == test["report"]["status_extended"]

    @mock_aws
    def test_ec2_open_sg_attached_to_allowed_eni_type(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPC
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        # Create Subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        # Get default security group
        default_sg = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Authorize ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Create Network Interface
        network_interface_response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[
                default_sg_id
            ],  # Associating the network interface with the default security group
            Description="Test Network Interface",
        )

        eni_type = network_interface_response["NetworkInterface"]["InterfaceType"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            audit_config={"ec2_allowed_interface_types": [eni_type]},
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) has at least one port open to the Internet and it is attached to an allowed network interface type ({eni_type})."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_aws
    def test_ec2_open_sg_attached_to_allowed_eni_owner(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPC
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        # Create Subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        # Get default security group
        default_sg = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Authorize ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Create Network Interface
        network_interface_response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[
                default_sg_id
            ],  # Associating the network interface with the default security group
            Description="Test Network Interface",
        )

        eni = network_interface_response.get("NetworkInterface", {})
        att = eni.get("Attachment", {})
        eni_owner = att.get("InstanceOwnerId", "")

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            audit_config={"ec2_allowed_instance_owners": [eni_owner]},
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) has at least one port open to the Internet and it is attached to an allowed network interface instance owner ({eni_owner})."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
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
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) does not have any port open to the Internet."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_aws
    def test_ec2_non_compliant_default_sg_open_to_one_port(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC
        vpc_response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc_response["Vpc"]["VpcId"]

        # Create Subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet_response["Subnet"]["SubnetId"]

        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]

        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        # Authorize ingress rule
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "FromPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "ToPort": 80,
                    "UserIdGroupPairs": [],
                }
            ],
        )

        # Create Network Interface
        network_interface_response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=[
                default_sg_id
            ],  # Associating the network interface with the default security group
            Description="Test Network Interface",
        )

        self.verify_check_fail(
            default_sg_id, default_sg_name, network_interface_response
        )

    @mock_aws
    def test_ec2_default_sgs_ignoring(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            scan_unused_services=False,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
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
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            scan_unused_services=False,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_default_sgs_with_any_ports_check(self):
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
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            expected_checks=[
                "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
            ],
            scan_unused_services=False,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                ec2_securitygroup_allow_ingress_from_internet_to_any_port,
            )

            check = ec2_securitygroup_allow_ingress_from_internet_to_any_port()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_non_compliant_default_sg_pass_to_avoid_fail_twice(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_client",
            new=EC2(aws_provider),
        ) as ec2_client_instance, mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.vpc_client",
            new=VPC(aws_provider),
        ) as vpc_client_instance:
            # Run check for all ports
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_all_ports.ec2_securitygroup_allow_ingress_from_internet_to_all_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_all_ports,
            )

            check_all_ports = (
                ec2_securitygroup_allow_ingress_from_internet_to_all_ports()
            )
            result_all_ports = check_all_ports.execute()

            # Verify that the all ports check has detected the issue
            assert any(
                sg.status == "FAIL" and sg.resource_id == default_sg_id
                for sg in result_all_ports
            )

            # use the same mock objects for the specific port check
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_client",
                new=ec2_client_instance,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port.vpc_client",
                new=vpc_client_instance,
            ):
                # Now run the specific port check
                from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_any_port.ec2_securitygroup_allow_ingress_from_internet_to_any_port import (
                    ec2_securitygroup_allow_ingress_from_internet_to_any_port,
                )

                check_specific_port = (
                    ec2_securitygroup_allow_ingress_from_internet_to_any_port()
                )
                result_specific_port = check_specific_port.execute()

                # One default sg per region
                assert len(result_specific_port) == 2
