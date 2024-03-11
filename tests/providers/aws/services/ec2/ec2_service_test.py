import ipaddress
import re
from base64 import b64decode
from datetime import datetime

from boto3 import client, resource
from dateutil.tz import tzutc
from freezegun import freeze_time
from moto import mock_aws

from prowler.providers.aws.services.ec2.ec2_service import EC2
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"
MOCK_DATETIME = datetime(2023, 1, 4, 7, 27, 30, tzinfo=tzutc())


class Test_EC2_Service:
    # Test EC2 Service
    @mock_aws
    def test_service(self):
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert ec2.service == "ec2"

    # Test EC2 Client
    @mock_aws
    def test_client(self):
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        for regional_client in ec2.regional_clients.values():
            assert regional_client.__class__.__name__ == "EC2"

    # Test EC2 Session
    @mock_aws
    def test__get_session__(self):
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert ec2.session.__class__.__name__ == "Session"

    # Test EC2 Session
    @mock_aws
    def test_audited_account(self):
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert ec2.audited_account == AWS_ACCOUNT_NUMBER

    # Test EC2 Describe Instances
    @mock_aws
    @freeze_time(MOCK_DATETIME)
    def test__describe_instances__(self):
        # Generate EC2 Client
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Get AMI image
        image_response = ec2_client.describe_images()
        image_id = image_response["Images"][0]["ImageId"]
        # Create EC2 Instances running
        ec2_resource.create_instances(
            MinCount=1,
            MaxCount=1,
            ImageId=image_id,
        )
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert len(ec2.instances) == 1
        assert re.match(r"i-[0-9a-z]{17}", ec2.instances[0].id)
        assert (
            ec2.instances[0].arn
            == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:instance/{ec2.instances[0].id}"
        )
        assert ec2.instances[0].type == "m1.small"
        assert ec2.instances[0].state == "running"
        assert re.match(r"ami-[0-9a-z]{8}", ec2.instances[0].image_id)
        assert ec2.instances[0].launch_time == MOCK_DATETIME
        assert not ec2.instances[0].user_data
        assert not ec2.instances[0].http_tokens
        assert not ec2.instances[0].http_endpoint
        assert not ec2.instances[0].instance_profile
        assert ipaddress.ip_address(ec2.instances[0].private_ip).is_private
        assert (
            ec2.instances[0].private_dns
            == f"ip-{ec2.instances[0].private_ip.replace('.', '-')}.ec2.internal"
        )
        assert ipaddress.ip_address(ec2.instances[0].public_ip).is_global
        assert (
            ec2.instances[0].public_dns
            == f"ec2-{ec2.instances[0].public_ip.replace('.', '-')}.compute-1.amazonaws.com"
        )

    # Test EC2 Describe Security Groups
    @mock_aws
    def test__describe_security_groups__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create EC2 Security Group
        sg_id = ec2_client.create_security_group(
            Description="test-description",
            GroupName="test-security-group",
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            expected_checks=[
                "ec2_securitygroup_allow_ingress_from_internet_to_any_port"
            ],
        )
        ec2 = EC2(audit_info)

        assert sg_id in str(ec2.security_groups)
        for security_group in ec2.security_groups:
            if security_group.id == sg_id:
                assert security_group.name == "test-security-group"
                assert (
                    security_group.arn
                    == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:security-group/{security_group.id}"
                )
                assert re.match(r"sg-[0-9a-z]{17}", security_group.id)
                assert security_group.region == AWS_REGION_US_EAST_1
                assert security_group.network_interfaces == []
                assert security_group.ingress_rules == [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ]
                assert security_group.egress_rules == [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ]
                assert security_group.public_ports
                assert security_group.tags == [
                    {"Key": "test", "Value": "test"},
                ]

    # Test EC2 Describe Nacls
    @mock_aws
    def test__describe_network_acls__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create EC2 VPC and SG
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_resource.create_network_acl(
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    "ResourceType": "network-acl",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        ).id
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert nacl_id in str(ec2.network_acls)
        for acl in ec2.network_acls:
            if acl.id == nacl_id:
                assert re.match(r"acl-[0-9a-z]{8}", acl.id)
                assert (
                    acl.arn
                    == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:network-acl/{acl.id}"
                )
                assert acl.entries == []
                assert acl.tags == [
                    {"Key": "test", "Value": "test"},
                ]

    # Test EC2 Describe Snapshots
    @mock_aws
    def test__describe_snapshots__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        snapshot_id = ec2_client.create_snapshot(
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
        snapshot_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:snapshot/{snapshot_id}"
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert snapshot_id in str(ec2.snapshots)
        assert ec2.volumes_with_snapshots[volume_id] is True

        for snapshot in ec2.snapshots:
            if snapshot.id == snapshot_id:
                assert re.match(r"snap-[0-9a-z]{8}", snapshot.id)
                assert snapshot.arn == snapshot_arn
                assert snapshot.region == AWS_REGION_US_EAST_1
                assert snapshot.tags == [
                    {"Key": "test", "Value": "test"},
                ]
                assert not snapshot.encrypted
                assert not snapshot.public

    # Test EC2 Get Snapshot Public
    @mock_aws
    def test__get_snapshot_public__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
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
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert snapshot_id in str(ec2.snapshots)
        for snapshot in ec2.snapshots:
            if snapshot.id == snapshot_id:
                assert re.match(r"snap-[0-9a-z]{8}", snapshot.id)
                assert (
                    snapshot.arn
                    == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:snapshot/{snapshot.id}"
                )
                assert snapshot.region == AWS_REGION_US_EAST_1
                assert not snapshot.encrypted
                assert snapshot.public

    # Test EC2 Instance User Data
    @mock_aws
    def test__get_instance_user_data__(self):
        user_data = "This is some user_data"
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert user_data == b64decode(ec2.instances[0].user_data).decode("utf-8")

    # Test EC2 Get EBS Encryption by default
    @mock_aws
    def test__get_ebs_encryption_by_default__(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.enable_ebs_encryption_by_default()
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        # One result per region
        assert len(ec2.ebs_encryption_by_default) == 2
        for result in ec2.ebs_encryption_by_default:
            if result.region == AWS_REGION_US_EAST_1:
                assert result.status

    # Test EC2 Describe Addresses
    @mock_aws
    def test__describe_addresses__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        allocation_id = ec2_client.allocate_address(
            Domain="vpc",
            Address="127.38.43.222",
            TagSpecifications=[
                {
                    "ResourceType": "elastic-ip",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["AllocationId"]
        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)
        assert "127.38.43.222" in str(ec2.elastic_ips)
        assert (
            ec2.elastic_ips[0].arn
            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"
        )
        assert ec2.elastic_ips[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test EC2 Describe Network Interfaces
    @mock_aws
    def test__describe_sg_network_interfaces__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC, Subnet, SecurityGroup and Network Interface
        vpc = ec2_resource.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2_resource.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        sg = ec2_resource.create_security_group(
            GroupName="test-securitygroup", Description="n/a"
        )
        eni_id = subnet.create_network_interface(Groups=[sg.id]).id
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id, Groups=[sg.id]
        )

        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert sg.id in str(ec2.security_groups)
        for security_group in ec2.security_groups:
            if security_group.id == sg.id:
                assert security_group.name == "test-securitygroup"
                assert (
                    security_group.arn
                    == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:security-group/{security_group.id}"
                )
                assert re.match(r"sg-[0-9a-z]{17}", security_group.id)
                assert security_group.region == AWS_REGION_US_EAST_1
                assert eni_id in security_group.network_interfaces
                assert security_group.ingress_rules == []
                assert security_group.egress_rules == [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ]

    @mock_aws
    def test__describe_public_network_interfaces__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC, Subnet, SecurityGroup and Network Interface
        vpc = ec2_resource.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2_resource.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")

        eni = subnet.create_network_interface(
            SubnetId=subnet.id,
            TagSpecifications=[
                {
                    "ResourceType": "network-interface",
                    "Tags": [
                        {"Key": "string", "Value": "string"},
                    ],
                },
            ],
        )
        eip = ec2_client.allocate_address(Domain="vpc")
        ec2_client.associate_address(
            NetworkInterfaceId=eni.id, AllocationId=eip["AllocationId"]
        )

        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert len(ec2.network_interfaces) == 1
        assert ec2.network_interfaces[0].public_ip == eip["PublicIp"]
        assert ec2.network_interfaces[0].private_ip == eni.private_ip_address
        assert ec2.network_interfaces[0].type == eni.interface_type
        assert ec2.network_interfaces[0].subnet_id == subnet.id
        assert ec2.network_interfaces[0].vpc_id == vpc.id
        assert ec2.network_interfaces[0].region == AWS_REGION_US_EAST_1
        assert ec2.network_interfaces[0].tags == [
            {"Key": "string", "Value": "string"},
        ]

    # Test EC2 Describe Images
    @mock_aws
    def test__describe_images__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create AMI
        tag_specifications = [
            {
                "ResourceType": "image",
                "Tags": [
                    {
                        "Key": "Base_AMI_Name",
                        "Value": "Deep Learning Base AMI (Amazon Linux 2) Version 31.0",
                    },
                    {"Key": "OS_Version", "Value": "AWS Linux 2"},
                ],
            },
        ]
        instance = ec2_resource.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1
        )[0]
        image_id = ec2_client.create_image(
            InstanceId=instance.instance_id,
            Name="test-image",
            Description="test ami",
            TagSpecifications=tag_specifications,
        )["ImageId"]

        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert len(ec2.images) == 1
        assert ec2.images[0].id == image_id
        assert re.match(r"ami-[0-9a-z]{8}", ec2.images[0].id)
        assert (
            ec2.images[0].arn
            == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:image/{ec2.images[0].id}"
        )
        assert not ec2.images[0].public
        assert ec2.images[0].region == AWS_REGION_US_EAST_1
        assert ec2.images[0].tags == [
            {
                "Key": "Base_AMI_Name",
                "Value": "Deep Learning Base AMI (Amazon Linux 2) Version 31.0",
            },
            {"Key": "OS_Version", "Value": "AWS Linux 2"},
        ]

    # Test EC2 Describe Volumes
    @mock_aws
    def test__describe_volumes__(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create Volume
        volume_id = ec2_client.create_volume(
            AvailabilityZone=AWS_REGION_US_EAST_1,
            Encrypted=False,
            Size=40,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["VolumeId"]

        # EC2 client for this test class
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        ec2 = EC2(audit_info)

        assert len(ec2.volumes) == 1
        assert ec2.volumes[0].id == volume_id
        assert re.match(r"vol-[0-9a-z]{8}", ec2.volumes[0].id)
        assert (
            ec2.volumes[0].arn
            == f"arn:{audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{ec2.volumes[0].id}"
        )
        assert ec2.volumes[0].region == AWS_REGION_US_EAST_1
        assert not ec2.volumes[0].encrypted
        assert ec2.volumes[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
