from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_securitygroup_in_use_without_ingress_filtering:
    @mock_ec2
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering import (
                ec2_securitygroup_in_use_without_ingress_filtering,
            )

            check = ec2_securitygroup_in_use_without_ingress_filtering()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # All are compliant by default
            assert result[0].status == "PASS"

    @mock_ec2
    def test_ec2_unused_public_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg_id = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering import (
                ec2_securitygroup_in_use_without_ingress_filtering,
            )

            check = ec2_securitygroup_in_use_without_ingress_filtering()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert search(
                        "has no ingress filtering and it is not being used",
                        sg.status_extended,
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )

    @mock_ec2
    def test_ec2_used_public_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg_id = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        ec2 = resource("ec2", region_name=AWS_REGION)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[
                default_sg_id,
            ],
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering import (
                ec2_securitygroup_in_use_without_ingress_filtering,
            )

            check = ec2_securitygroup_in_use_without_ingress_filtering()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert search(
                        "has no ingress filtering and it is being used",
                        sg.status_extended,
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )

    @mock_ec2
    def test_ec2_private_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg_id = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]["GroupId"]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_in_use_without_ingress_filtering.ec2_securitygroup_in_use_without_ingress_filtering import (
                ec2_securitygroup_in_use_without_ingress_filtering,
            )

            check = ec2_securitygroup_in_use_without_ingress_filtering()
            result = check.execute()

            # One default sg per region
            assert len(result) == 3
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert search(
                        "has ingress filtering",
                        sg.status_extended,
                    )
                    assert (
                        sg.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:security-group/{default_sg_id}"
                    )
