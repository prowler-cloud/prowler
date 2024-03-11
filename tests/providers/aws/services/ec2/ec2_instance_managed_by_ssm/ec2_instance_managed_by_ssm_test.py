from unittest import mock

from boto3 import resource
from moto import mock_aws

from prowler.providers.aws.services.ssm.ssm_service import ManagedInstance
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_managed_by_ssm_test:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_client.ssm_client",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm import (
                ec2_instance_managed_by_ssm,
            )

            check = ec2_instance_managed_by_ssm()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_instance_managed_by_ssm_non_compliance_instance(self):
        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {}

        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {}

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_client.ssm_client",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm import (
                ec2_instance_managed_by_ssm,
            )

            check = ec2_instance_managed_by_ssm()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} is not managed by Systems Manager."
            )
            assert result[0].resource_id == instance.id

    @mock_aws
    def test_ec2_instance_managed_by_ssm_compliance_instance(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {
            instance.id: ManagedInstance(
                arn=f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:instance/{instance.id}",
                id=instance.id,
                region=AWS_REGION_US_EAST_1,
            )
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ssm.ssm_client.ssm_client",
            new=ssm_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm import (
                ec2_instance_managed_by_ssm,
            )

            check = ec2_instance_managed_by_ssm()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} is managed by Systems Manager."
            )
            assert result[0].resource_id == instance.id
