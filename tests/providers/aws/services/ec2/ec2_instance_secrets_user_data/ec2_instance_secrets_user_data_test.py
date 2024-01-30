from os import path
from pathlib import Path
from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"


class Test_ec2_instance_secrets_user_data:
    @mock_aws
    def test_no_ec2(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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

    @mock_aws
    def test_one_ec2_with_no_secrets(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_with_secrets(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="DB_PASSWORD=foobar123",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Secret Keyword on line 1."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "r",
        )
        secrets = f.read()
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=secrets
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Secret Keyword on line 1, Hex High Entropy String on line 3, Secret Keyword on line 3, Secret Keyword on line 4."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_configurations_without_user_data(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=""
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_file_with_secrets_gzip(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture.gz",
            "rb",
        )
        secrets = f.read()
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=secrets
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Secret Keyword on line 1, Hex High Entropy String on line 3, Secret Keyword on line 3, Secret Keyword on line 4."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1
