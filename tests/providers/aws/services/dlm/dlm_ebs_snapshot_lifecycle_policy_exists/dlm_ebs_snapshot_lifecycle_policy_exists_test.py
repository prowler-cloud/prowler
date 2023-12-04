from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.dlm.dlm_service import LifecyclePolicy
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

LIFECYCLE_POLICY_ID = "policy-XXXXXXXXXXXX"


class Test_dlm_ebs_snapshot_lifecycle_policy_exists:
    def set_mocked_audit_info(self):
        return AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audit_config=None,
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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

    @mock_ec2
    def test_no_ebs_snapshot_no_lifecycle_policies(self):
        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {}

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.DLM",
            new=dlm_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_service.EC2",
            return_value=EC2(audit_info),
        ) as ec2_client, mock.patch(
            "prowler.providers.aws.services.ec2.ec2_client.ec2_client",
            new=ec2_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0

    @mock_ec2
    def test_one_ebs_snapshot_and_dlm_lifecycle_policy(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        _ = ec2_client.create_snapshot(
            VolumeId=volume_id,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["SnapshotId"]

        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {
            AWS_REGION: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "EBS snapshot lifecycle policies found."
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

    @mock_ec2
    def test_one_ebs_snapshot_and_no_dlm_lifecycle_policy(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        _ = ec2_client.create_snapshot(
            VolumeId=volume_id,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["SnapshotId"]

        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {}

        # from prowler.providers.aws.services.ec2.ec2_service import EC2

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0

    @mock_ec2
    def test_no_ebs_snapshot_and_dlm_lifecycle_policy(self):
        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {
            AWS_REGION: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }

        # from prowler.providers.aws.services.ec2.ec2_service import EC2

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ) as ec2_client, mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            # Remove all snapshots
            ec2_client.regions_with_snapshots = {}

            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0
