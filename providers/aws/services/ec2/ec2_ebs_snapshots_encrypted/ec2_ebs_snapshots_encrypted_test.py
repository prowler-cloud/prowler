from unittest import mock

from boto3 import resource
from moto import mock_ec2

AWS_REGION = "us-east-1"


class Test_ec2_ebs_snapshots_encrypted:
    @mock_ec2
    def test_ec2_default_snapshots(self):

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            result = check.execute()

            # Default snapshots
            assert len(result) == 1433

    @mock_ec2
    def test_ec2_unencrypted_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")
        snapshot = volume.create_snapshot(Description="testsnap")

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 1434

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.status == "FAIL"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is unencrypted."
                    )

    @mock_ec2
    def test_ec2_encrypted_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        snapshot = volume = ec2.create_volume(
            Size=80, AvailabilityZone=f"{AWS_REGION}a", Encrypted=True
        )
        snapshot = volume.create_snapshot(Description="testsnap")
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 1434

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.status == "PASS"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is encrypted."
                    )
