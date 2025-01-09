from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports:
    @mock_aws
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
            )
            result = check.execute()

            assert (
                len(result) == 3
            )  # 3 security groups one default sg per region and one added
            # Search changed sg
            for sg in result:
                # All are compliant by default
                assert sg.status == "PASS"

    @mock_aws
    def test_ec2_non_compliant_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        security_groups = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ]
        default_sg_id = security_groups[0]["GroupId"]
        default_sg_name = security_groups[0]["GroupName"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 20,
                    "ToPort": 9000,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
            )
            result = check.execute()

            assert (
                len(result) == 3
            )  # 3 security groups one default sg per region and one added
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has the following high-risk ports open to the Internet: 25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088."
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
                    "IpProtocol": "tcp",
                    "FromPort": 20,
                    "ToPort": 9000,
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
                }
            ],
        )
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
            )
            result = check.execute()

            assert (
                len(result) == 3
            )  # 3 security groups one default sg per region and one added
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) does not have any high-risk port open to the Internet."
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
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }

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
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
            )
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
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }
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
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
            new=EC2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
            )
            result = check.execute()

            assert len(result) == 1  # 1 security group added
            for sg in result:
                assert sg.status == "PASS"
                assert sg.region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_non_compliant_default_sg_pass_to_avoid_fail_twice(self):
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
        ec2_client.audit_config = {
            "ec2_high_risk_ports": [
                25,
                110,
                135,
                143,
                445,
                3000,
                4333,
                5000,
                5500,
                8080,
                8088,
            ]
        }

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
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_client",
                new=ec2_client_instance,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.vpc_client",
                new=vpc_client_instance,
            ):
                # Now run the specific port check
                from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports.ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports import (
                    ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports,
                )

                check_specific_port = (
                    ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports()
                )
                result_specific_port = check_specific_port.execute()

                assert (
                    len(result_specific_port) == 3
                )  # 3 security groups one default sg per region and one added
                # Search changed sg
                for sg in result_specific_port:
                    if sg.resource_id == default_sg_id:
                        assert sg.status == "PASS"
                        assert sg.region == AWS_REGION_US_EAST_1
                        assert (
                            sg.status_extended
                            == f"Security group {default_sg_name} ({default_sg_id}) has all ports open to the Internet and therefore was not checked against high-risk ports."
                        )
                        assert (
                            sg.resource_arn
                            == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:security-group/{default_sg_id}"
                        )
                        assert sg.resource_details == default_sg_name
                        assert sg.resource_tags == []
