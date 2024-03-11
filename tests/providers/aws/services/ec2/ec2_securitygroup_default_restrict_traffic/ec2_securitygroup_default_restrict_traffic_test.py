from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_ec2_securitygroup_default_restrict_traffic:
    @mock_aws
    def test_ec2_compliant_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]
        ec2_client.revoke_security_group_egress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic import (
                ec2_securitygroup_default_restrict_traffic,
            )

            check = ec2_securitygroup_default_restrict_traffic()
            result = check.execute()

            # One default sg per region
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Default Security Group ({default_sg_id}) rules do not allow traffic."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.identity.account}:security-group/{default_sg_id}"
            )
            assert result[0].resource_details == default_sg_name
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == default_sg_id

    @mock_aws
    def test_ec2_non_compliant_sg_ingress_rule(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.16/0"}]}
            ],
        )
        ec2_client.revoke_security_group_egress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic import (
                ec2_securitygroup_default_restrict_traffic,
            )

            check = ec2_securitygroup_default_restrict_traffic()
            result = check.execute()

            # One default sg per region
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Default Security Group ({default_sg_id}) rules allow traffic."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.identity.account}:security-group/{default_sg_id}"
            )
            assert result[0].resource_details == default_sg_name
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == default_sg_id

    @mock_aws
    def test_ec2_non_compliant_sg_egress_rule(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        default_sg_name = default_sg["GroupName"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_default_restrict_traffic.ec2_securitygroup_default_restrict_traffic import (
                ec2_securitygroup_default_restrict_traffic,
            )

            check = ec2_securitygroup_default_restrict_traffic()
            result = check.execute()

            # One default sg per region
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Default Security Group ({default_sg_id}) rules allow traffic."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.identity.account}:security-group/{default_sg_id}"
            )
            assert result[0].resource_details == default_sg_name
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == default_sg_id
