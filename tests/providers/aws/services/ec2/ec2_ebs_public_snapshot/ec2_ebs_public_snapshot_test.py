from unittest import mock

from boto3 import client, resource, session
from mock import patch
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.services.ec2.ec2_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ec2_ebs_public_snapshot:
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
        )

        return audit_info

    @mock_ec2
    def test_ec2_default_snapshots(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            result = check.execute()

            # Default snapshots
            assert len(result) == 565

    @mock_ec2
    def test_ec2_public_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        ec2_client = client("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        snapshot = volume.create_snapshot(Description="testsnap")
        ec2_client.modify_snapshot_attribute(
            SnapshotId=snapshot.id,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 566

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.status == "FAIL"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is currently Public."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:snapshot/{snapshot.id}"
                    )

    @mock_ec2
    def test_ec2_private_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        snapshot = volume = ec2.create_volume(
            Size=80, AvailabilityZone=f"{AWS_REGION}a", Encrypted=True
        )
        snapshot = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 566

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.status == "PASS"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is not Public."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:snapshot/{snapshot.id}"
                    )
