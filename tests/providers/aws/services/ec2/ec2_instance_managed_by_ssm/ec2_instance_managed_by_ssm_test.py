from unittest import mock

from boto3 import resource, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ssm.ssm_service import ManagedInstance
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_ec2_instance_managed_by_ssm_test:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_ec2
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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

    @mock_ec2
    def test_ec2_instance_managed_by_ssm_non_compliance_instance(self):
        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {}

        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} is not managed by Systems Manager."
            )
            assert result[0].resource_id == instance.id

    @mock_ec2
    def test_ec2_instance_managed_by_ssm_compliance_instance(self):
        ec2 = resource("ec2", region_name=AWS_REGION)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        ssm_client = mock.MagicMock
        ssm_client.managed_instances = {
            instance.id: ManagedInstance(
                arn=f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:instance/{instance.id}",
                id=instance.id,
                region=AWS_REGION,
            )
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} is managed by Systems Manager."
            )
            assert result[0].resource_id == instance.id
