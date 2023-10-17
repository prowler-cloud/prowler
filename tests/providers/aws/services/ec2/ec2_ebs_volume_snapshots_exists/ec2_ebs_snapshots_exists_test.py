from unittest import mock

from boto3 import resource, session
from mock import patch
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_REGION_AZ = "us-east-1a"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


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
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
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
    def test_no_volumes(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_volume_without_snapshots(self):
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume_arn = f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Snapshots not found for the EBS volume {volume.id}."
            )
            assert result[0].resource_id == volume.id
            assert result[0].resource_arn == volume_arn
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION

    @mock_ec2
    def test_ec2_volume_with_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume_arn = f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        _ = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Snapshots found for the EBS volume {result[0].resource_id}."
            )
            assert result[0].resource_id == volume.id
            assert result[0].resource_arn == volume_arn
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION

    @mock_ec2
    def test_ec2_volume_with_and_without_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)

        volume1 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume1_arn = (
            f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:volume/{volume1.id}"
        )
        _ = volume1.create_snapshot(Description="test-snap")

        volume2 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume2_arn = (
            f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:volume/{volume2.id}"
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 2
            for res in result:
                if res.resource_id == volume1.id:
                    assert res.status == "PASS"
                    assert (
                        res.status_extended
                        == f"Snapshots found for the EBS volume {res.resource_id}."
                    )
                    assert res.resource_id == volume1.id
                    assert res.resource_arn == volume1_arn
                    assert res.resource_tags is None
                    assert res.region == AWS_REGION
                if res.resource_id == volume2.id:
                    assert res.status == "FAIL"
                    assert (
                        res.status_extended
                        == f"Snapshots not found for the EBS volume {res.resource_id}."
                    )
                    assert res.resource_id == volume2.id
                    assert res.resource_arn == volume2_arn
                    assert res.resource_tags is None
                    assert res.region == AWS_REGION
