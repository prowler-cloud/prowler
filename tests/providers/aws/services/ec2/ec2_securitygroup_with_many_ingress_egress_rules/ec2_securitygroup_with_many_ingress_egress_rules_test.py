from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_ec2_securitygroup_with_many_ingress_egress_rules:
    @mock_aws
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        current_audit_info.audit_config = {"max_security_group_rules": 50}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules import (
                ec2_securitygroup_with_many_ingress_egress_rules,
            )

            check = ec2_securitygroup_with_many_ingress_egress_rules()
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
        for i in range(60):
            ec2_client.authorize_security_group_ingress(
                GroupId=default_sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": i,
                        "ToPort": i,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        current_audit_info.audit_config = {"max_security_group_rules": 50}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules import (
                ec2_securitygroup_with_many_ingress_egress_rules,
            )

            check = ec2_securitygroup_with_many_ingress_egress_rules()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) has 60 inbound rules and 1 outbound rules."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
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
                    "FromPort": 23,
                    "ToPort": 23,
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        current_audit_info.audit_config = {"max_security_group_rules": 50}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_with_many_ingress_egress_rules.ec2_securitygroup_with_many_ingress_egress_rules import (
                ec2_securitygroup_with_many_ingress_egress_rules,
            )

            check = ec2_securitygroup_with_many_ingress_egress_rules()
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
                        == f"Security group {default_sg_name} ({default_sg_id}) has 1 inbound rules and 1 outbound rules."
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )
                    assert sg.resource_details == default_sg_name
                    assert sg.resource_tags == []
