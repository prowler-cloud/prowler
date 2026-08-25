from ipaddress import IPv4Address, IPv6Address
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip"
    ".ec2_confidential_workload_host_public_ip"
)


def _create_enclave_instance(subnet_id=None, associate_public_ip=False):
    ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
    kwargs = dict(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
    if subnet_id:
        kwargs["NetworkInterfaces"] = [
            {
                "SubnetId": subnet_id,
                "DeviceIndex": 0,
                "AssociatePublicIpAddress": associate_public_ip,
            }
        ]
    return ec2.create_instances(**kwargs)[0]


class Test_ec2_confidential_workload_host_public_ip:
    @mock_aws
    def test_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)),
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            assert ec2_confidential_workload_host_public_ip().execute() == []

    @mock_aws
    def test_enclave_in_private_subnet_no_public_ip_pass(self):
        instance = _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)) as vpcc,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = None
            subnet = vpcc.vpc_subnets.get(ec2c.instances[0].subnet_id)
            if subnet is not None:
                subnet.public = False

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance.id
            assert "not in a public subnet" in result[0].status_extended

    @mock_aws
    def test_enclave_with_public_ip_fail(self):
        instance = _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)) as vpcc,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = "203.0.113.10"
            subnet = vpcc.vpc_subnets.get(ec2c.instances[0].subnet_id)
            if subnet is not None:
                subnet.public = False

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "203.0.113.10" in result[0].status_extended

    @mock_aws
    def test_enclave_in_public_subnet_fail(self):
        ec2c = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2c.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2c.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"][
            "SubnetId"
        ]
        igw_id = ec2c.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2c.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        rt_id = ec2c.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
        ec2c.create_route(
            RouteTableId=rt_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw_id,
        )
        ec2c.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)

        instance = _create_enclave_instance(subnet_id=subnet_id)

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2mc,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2mc.instances[0].enclaves_enabled = True
            ec2mc.instances[0].public_ip = None

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "internet gateway" in result[0].status_extended

    @mock_aws
    def test_enclave_with_global_ipv6_on_eni_fail(self):
        instance = _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)) as vpcc,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = None
            subnet = vpcc.vpc_subnets.get(ec2c.instances[0].subnet_id)
            if subnet is not None:
                subnet.public = False
                subnet.public_ipv6 = False

            eni_id = ec2c.instances[0].network_interfaces[0]
            ec2c.network_interfaces[eni_id].public_ip_addresses = [
                IPv6Address("2001:db8::1")
            ]

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "2001:db8::1" in result[0].status_extended
            assert "global IPv6" in result[0].status_extended

    @mock_aws
    def test_enclave_in_ipv6_only_public_subnet_fail(self):
        ec2c = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2c.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2c.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"][
            "SubnetId"
        ]
        igw_id = ec2c.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2c.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        rt_id = ec2c.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
        # IPv6-only default route to IGW; no 0.0.0.0/0 → IGW here.
        ec2c.create_route(
            RouteTableId=rt_id,
            DestinationIpv6CidrBlock="::/0",
            GatewayId=igw_id,
        )
        ec2c.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)

        instance = _create_enclave_instance(subnet_id=subnet_id)

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2mc,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2mc.instances[0].enclaves_enabled = True
            ec2mc.instances[0].public_ip = None

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "::/0" in result[0].status_extended

    @mock_aws
    def test_enclave_with_both_public_ipv4_and_global_ipv6_fail(self):
        instance = _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)) as vpcc,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = "203.0.113.10"
            subnet = vpcc.vpc_subnets.get(ec2c.instances[0].subnet_id)
            if subnet is not None:
                subnet.public = False
                subnet.public_ipv6 = False

            eni_id = ec2c.instances[0].network_interfaces[0]
            ec2c.network_interfaces[eni_id].public_ip_addresses = [
                IPv4Address("203.0.113.10"),
                IPv6Address("2001:db8::1"),
            ]

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "203.0.113.10" in result[0].status_extended
            assert "2001:db8::1" in result[0].status_extended

    @mock_aws
    def test_enclave_with_ipv4_public_ip_but_no_global_ipv6_pass_still_fail(self):
        # Regression: only IPv4 in public_ip_addresses on the ENI must not
        # be mistaken for an IPv6 signal. FAIL comes solely from
        # instance.public_ip; the ENI IPv6 reason must NOT appear.
        instance = _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)) as vpcc,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = "203.0.113.10"
            subnet = vpcc.vpc_subnets.get(ec2c.instances[0].subnet_id)
            if subnet is not None:
                subnet.public = False
                subnet.public_ipv6 = False

            eni_id = ec2c.instances[0].network_interfaces[0]
            ec2c.network_interfaces[eni_id].public_ip_addresses = [
                IPv4Address("203.0.113.10")
            ]

            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "203.0.113.10" in result[0].status_extended
            assert "global IPv6" not in result[0].status_extended

    @mock_aws
    def test_non_enclave_instance_skipped(self):
        _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=VPC(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = False
            ec2c.instances[0].public_ip = "203.0.113.10"

            assert ec2_confidential_workload_host_public_ip().execute() == []

    @mock_aws
    def test_missing_subnet_reports_manual_not_pass(self):
        # A subnet ID that isn't resolvable in vpc_client means we cannot
        # verify subnet exposure — MANUAL, not PASS.
        _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ec2_svc = EC2(aws_provider)
        vpc_svc = VPC(aws_provider)
        # Force subnet resolution to fail.
        vpc_svc.vpc_subnets = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=ec2_svc) as ec2c,
            mock.patch(f"{CHECK_MODULE}.vpc_client", new=vpc_svc),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_public_ip.ec2_confidential_workload_host_public_ip import (
                ec2_confidential_workload_host_public_ip,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].public_ip = None
            result = ec2_confidential_workload_host_public_ip().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "cannot be fully verified" in result[0].status_extended
            assert "subnet" in result[0].status_extended
