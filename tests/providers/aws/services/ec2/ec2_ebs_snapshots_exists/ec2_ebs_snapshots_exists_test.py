from unittest import mock

from boto3 import resource, session
from mock import patch
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ec2_ebs_snapshots_exists:
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
    def test_ec2_volume_without_snapshots(self):
        ec2 = resource("ec2", region_name=AWS_REGION)
        _ = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists import (
                ec2_ebs_snapshots_exists,
            )

            check = ec2_ebs_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Snapshots not found to EBS volume {result[0].resource_id}"
            )

    @mock_ec2
    def test_ec2_volume_with_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        _ = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists import (
                ec2_ebs_snapshots_exists,
            )

            check = ec2_ebs_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Snapshots found to EBS volume {result[0].resource_id}"
            )

    @mock_ec2
    def test_ec2_volume_with_and_without_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume1 = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        _ = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        _ = volume1.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_exists.ec2_ebs_snapshots_exists import (
                ec2_ebs_snapshots_exists,
            )

            check = ec2_ebs_snapshots_exists()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Snapshots found to EBS volume {result[0].resource_id}"
            )
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"Snapshots not found to EBS volume {result[1].resource_id}"
            )
