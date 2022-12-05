from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_securitygroup_from_launch_wizard:
    @mock_ec2
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard import (
                ec2_securitygroup_from_launch_wizard,
            )

            check = ec2_securitygroup_from_launch_wizard()
            result = check.execute()

            # One default sg per region
            assert len(result) == 26
            # All are compliant by default
            assert result[0].status == "PASS"

    @mock_ec2
    def test_ec2_launch_wizard_sg(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        sg_id = ec2_client.create_security_group(
            GroupName="launch-wizard-1", Description="launch wizard sg"
        )["GroupId"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard import (
                ec2_securitygroup_from_launch_wizard,
            )

            check = ec2_securitygroup_from_launch_wizard()
            result = check.execute()

            # One default sg per region + created one
            assert len(result) == 27
            # Search changed sg
            for sg in result:
                if sg.resource_id == sg_id:
                    assert sg.status == "FAIL"
                    assert search(
                        "was created using the EC2 Launch Wizard",
                        sg.status_extended,
                    )

    @mock_ec2
    def test_ec2_compliant_default_sg(self):
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
            "providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_securitygroup_from_launch_wizard.ec2_securitygroup_from_launch_wizard import (
                ec2_securitygroup_from_launch_wizard,
            )

            check = ec2_securitygroup_from_launch_wizard()
            result = check.execute()

            # One default sg per region
            assert len(result) == 26
            # Search changed sg
            for sg in result:
                if sg.resource_id == default_sg_id:
                    assert sg.status == "PASS"
                    assert search(
                        "was not created using the EC2 Launch Wizard",
                        sg.status_extended,
                    )
