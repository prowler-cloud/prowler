from base64 import b64decode

from boto3 import client, resource, session
from moto import mock_ec2

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.ec2.ec2_service import EC2

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_EC2_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
        )
        return audit_info

    # Test EC2 Service
    @mock_ec2
    def test_service(self):
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert ec2.service == "ec2"

    # Test EC2 Client
    @mock_ec2
    def test_client(self):
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        for regional_client in ec2.regional_clients.values():
            assert regional_client.__class__.__name__ == "EC2"

    # Test EC2 Session
    @mock_ec2
    def test__get_session__(self):
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert ec2.session.__class__.__name__ == "Session"

    # Test EC2 Session
    @mock_ec2
    def test_audited_account(self):
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert ec2.audited_account == AWS_ACCOUNT_NUMBER

    # Test EC2 Describe Instances
    @mock_ec2
    def test__describe_instances__(self):
        # Generate EC2 Client
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        ec2_client = client("ec2", region_name=AWS_REGION)
        # Get AMI image
        image_response = ec2_client.describe_images()
        image_id = image_response["Images"][0]["ImageId"]
        # Create EC2 Instances
        ec2_resource.create_instances(
            MinCount=2,
            MaxCount=2,
            ImageId=image_id,
        )
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert len(ec2.instances) == len(
            ec2_client.describe_instances()["Reservations"][0]["Instances"]
        )

    # Test EC2 Describe Security Groups
    @mock_ec2
    def test__describe_security_groups__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        # Create EC2 Security Group
        sg_id = ec2_client.create_security_group(
            Description="test-description",
            GroupName="test-security-group",
        )["GroupId"]
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert sg_id in str(ec2.security_groups)

    # Test EC2 Describe Nacls
    @mock_ec2
    def test__describe_network_acls__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        # Create EC2 VPC and SG
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_resource.create_network_acl(
            VpcId=vpc_id,
        ).id
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert nacl_id in str(ec2.network_acls)

    # Test EC2 Describe Snapshots
    @mock_ec2
    def test__describe_snapshots__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        snapshot_id = ec2_client.create_snapshot(
            VolumeId=volume_id,
        )["SnapshotId"]
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert snapshot_id in str(ec2.snapshots)

    # Test EC2 Get Snapshot Public
    @mock_ec2
    def test__get_snapshot_public__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        snapshot_id = ec2_client.create_snapshot(
            VolumeId=volume_id,
        )["SnapshotId"]
        ec2_client.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            GroupNames=[
                "all",
            ],
            OperationType="add",
            SnapshotId=snapshot_id,
        )
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        for snapshot in ec2.snapshots:
            if snapshot.id == snapshot_id:
                assert snapshot.public

    # Test EC2 Instance User Data
    @mock_ec2
    def test__get_instance_user_data__(self):
        user_data = "This is some user_data"
        ec2 = resource("ec2", region_name=AWS_REGION)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert user_data == b64decode(ec2.instances[0].user_data).decode("utf-8")

    # Test EC2 Instance User Data
    @mock_ec2
    def test__get_ebs_encryption_by_default__(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.enable_ebs_encryption_by_default()
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)

        # One result per region
        assert len(ec2.ebs_encryption_by_default) == 25
        for result in ec2.ebs_encryption_by_default:
            if result.region == AWS_REGION:
                assert result.status

    # Test EC2 Describe Snapshots
    @mock_ec2
    def test__describe_addresses__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        allocation_id = ec2_client.allocate_address(
            Domain="vpc", Address="127.38.43.222"
        )["AllocationId"]
        # EC2 client for this test class
        audit_info = self.set_mocked_audit_info()
        ec2 = EC2(audit_info)
        assert "127.38.43.222" in str(ec2.elastic_ips)
        assert (
            ec2.elastic_ips[0].arn
            == f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"
        )
