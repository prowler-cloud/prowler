from boto3 import client, session
from moto import mock_ec2

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.vpc.vpc_service import VPC

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"


class Test_VPC_Service:
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

    # Test VPC Service
    @mock_ec2
    def test_service(self):
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        assert vpc.service == "ec2"

    # Test VPC Client
    @mock_ec2
    def test_client(self):
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        for client in vpc.regional_clients.values():
            assert client.__class__.__name__ == "EC2"

    # Test VPC Session
    @mock_ec2
    def test__get_session__(self):
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        assert vpc.session.__class__.__name__ == "Session"

    # Test VPC Session
    @mock_ec2
    def test_audited_account(self):
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        assert vpc.audited_account == AWS_ACCOUNT_NUMBER

    # Test VPC Describe VPCs
    @mock_ec2
    def test__describe_vpcs__(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        # Create VPC
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        assert (
            len(vpc.vpcs) == 24
        )  # Number of AWS regions + created VPC, one default VPC per region

    # Test VPC Describe Flow Logs
    @mock_ec2
    def test__describe_flow_logs__(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        new_vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        # Create VPC Flow log
        ec2_client.create_flow_logs(
            ResourceType="VPC",
            ResourceIds=[new_vpc["VpcId"]],
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="test_logs",
            DeliverLogsPermissionArn="arn:aws:iam::"
            + str(AWS_ACCOUNT_NUMBER)
            + ":role/test-role",
        )
        # VPC client for this test class
        audit_info = self.set_mocked_audit_info()
        vpc = VPC(audit_info)
        # Search created VPC among default ones
        for vpc in vpc.vpcs:
            if vpc.id == new_vpc["VpcId"]:
                assert vpc.flow_log == True
