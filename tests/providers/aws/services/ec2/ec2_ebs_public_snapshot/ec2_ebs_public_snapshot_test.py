from unittest import mock

from boto3 import client, resource
from moto import mock_ec2

AWS_REGION = "us-east-1"


class Test_ec2_ebs_public_snapshot:
    @mock_ec2
    def test_ec2_default_snapshots(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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
            assert len(result) == 1116

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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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
            assert len(results) == 1117

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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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
            assert len(results) == 1117

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
