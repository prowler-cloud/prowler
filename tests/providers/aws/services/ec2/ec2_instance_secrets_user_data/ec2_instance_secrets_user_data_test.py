from unittest import mock

from boto3 import resource
from moto import mock_ec2

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_secrets_user_data:
    @mock_ec2
    def test_no_ec2(self):

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_one_ec2_with_no_secrets(self):

        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in EC2 instance {instance.id} User Data."
            )
            assert result[0].resource_id == instance.id

    @mock_ec2
    def test_one_ec2_with_secrets(self):

        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="DB_PASSWORD=foobar123",
        )[0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in EC2 instance {instance.id} User Data."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:instance/{instance.id}"
            )

    @mock_ec2
    def test_one_ec2_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            "prowler/providers/aws/services/ec2/ec2_instance_secrets_user_data/fixtures/fixture",
            "r",
        )
        secrets = f.read()
        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=secrets
        )[0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in EC2 instance {instance.id} User Data."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:instance/{instance.id}"
            )

    @mock_ec2
    def test_one_launch_configurations_without_user_data(self):

        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=""
        )[0]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in EC2 instance {instance.id} since User Data is empty."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
