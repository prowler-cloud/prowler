from unittest import mock

from boto3 import client, resource
from moto import mock_ec2

from prowler.providers.aws.services.vpc.vpc_service import VPC
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379:
    @mock_ec2
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client_us_east_1 = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client_us_east_1.create_vpc(CidrBlock="10.0.0.0/16")
        sgs_us_east_1 = ec2_client_us_east_1.describe_security_groups()[
            "SecurityGroups"
        ]

        ec2_client_eu_west_1 = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        sgs_eu_west_1 = ec2_client_eu_west_1.describe_security_groups()[
            "SecurityGroups"
        ]
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379()
            )
            result = check.execute()

            # One default sg per region + VPC
            assert len(result) == 3

            # All are compliant by default
            # 2 in us-east-1
            for sg in sgs_us_east_1:
                for res in result:
                    if res.resource_id == sg["GroupId"]:
                        assert res.status == "PASS"
                        assert res.region == AWS_REGION_US_EAST_1
                        assert (
                            res.status_extended
                            == f"Security group {sg['GroupName']} ({sg['GroupId']}) does not have Redis port 6379 open to the Internet."
                        )
                        assert (
                            res.resource_arn
                            == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg['GroupId']}"
                        )
                        assert res.resource_details == sg["GroupName"]
                        assert res.resource_tags == []

            # 1 in eu-west-1
            for sg in sgs_eu_west_1:
                for res in result:
                    if res.resource_id == sg["GroupId"]:
                        assert res.status == "PASS"
                        assert res.region == AWS_REGION_EU_WEST_1
                        assert (
                            res.status_extended
                            == f"Security group {sg['GroupName']} ({sg['GroupId']}) does not have Redis port 6379 open to the Internet."
                        )
                        assert (
                            res.resource_arn
                            == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_EU_WEST_1}:{current_audit_info.audited_account}:security-group/{sg['GroupId']}"
                        )
                        assert res.resource_details == sg["GroupName"]
                        assert res.resource_tags == []

    @mock_ec2
    def test_ec2_non_compliant_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client_us_east_1 = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client_us_east_1.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client_us_east_1.describe_security_groups(
            GroupNames=["default"]
        )["SecurityGroups"][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]
        ec2_client_us_east_1.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 6379,
                    "ToPort": 6379,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379()
            )
            result = check.execute()

            # One default sg per region + VPC
            assert len(result) == 3

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) has Redis port 6379 open to the Internet."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_ec2
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
                    "FromPort": 6379,
                    "ToPort": 6379,
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379()
            )
            result = check.execute()

            # One default sg per region
            assert len(result) == 3

            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert sg.region == AWS_REGION_US_EAST_1
                    assert (
                        sg.status_extended
                        == f"Security group {default_sg_name} ({default_sg_id}) does not have Redis port 6379 open to the Internet."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []

    @mock_ec2
    def test_ec2_default_sgs_ignoring(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379()
            )
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_default_sgs_ignoring_vpc_in_use(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        ec2.create_network_interface(SubnetId=subnet.id)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        sgs_us_east_1 = ec2_client.describe_security_groups()["SecurityGroups"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info()
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.vpc_client",
            new=VPC(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379.ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379 import (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379,
            )

            check = (
                ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379()
            )
            result = check.execute()

            assert len(result) == 1

            for sg in sgs_us_east_1:
                if sg["GroupId"] == result[0].resource_id:
                    assert result[0].status == "PASS"
                    assert result[0].region == AWS_REGION_US_EAST_1
                    assert (
                        result[0].status_extended
                        == f"Security group {sg['GroupName']} ({sg['GroupId']}) does not have Redis port 6379 open to the Internet."
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg['GroupId']}"
                    )
                    assert result[0].resource_details == sg["GroupName"]
                    assert result[0].resource_tags == []
