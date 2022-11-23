from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_securitygroup_not_used:
    @mock_ec2
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One default sg per region
            assert len(result) == 26
            # All are unused by default
            assert result[0].status == "FAIL"

    @mock_ec2
    def test_ec2_unused_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg_id = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]["GroupId"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One default sg per region
            assert len(result) == 26
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "FAIL"
                    assert search(
                        "it is not being used",
                        sg.status_extended,
                    )

    @mock_ec2
    def test_ec2_used_default_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg_id = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]["GroupId"]

        ec2 = resource("ec2", region_name=AWS_REGION)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[
                default_sg_id,
            ],
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One default sg per region
            assert len(result) == 26
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert search(
                        "it is being used",
                        sg.status_extended,
                    )
