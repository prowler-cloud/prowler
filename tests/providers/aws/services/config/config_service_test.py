from boto3 import client, session
from moto import mock_config

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.config.config_service import Config

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_Config_Service:
    # Mocked Audit Info
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
            audited_regions=["eu-west-1", "us-east-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        return audit_info

    # Test Config Service
    @mock_config
    def test_service(self):
        # Config client for this test class
        audit_info = self.set_mocked_audit_info()
        config = Config(audit_info)
        assert config.service == "config"

    # Test Config Client
    @mock_config
    def test_client(self):
        # Config client for this test class
        audit_info = self.set_mocked_audit_info()
        config = Config(audit_info)
        for regional_client in config.regional_clients.values():
            assert regional_client.__class__.__name__ == "ConfigService"

    # Test Config Session
    @mock_config
    def test__get_session__(self):
        # Config client for this test class
        audit_info = self.set_mocked_audit_info()
        config = Config(audit_info)
        assert config.session.__class__.__name__ == "Session"

    # Test Config Session
    @mock_config
    def test_audited_account(self):
        # Config client for this test class
        audit_info = self.set_mocked_audit_info()
        config = Config(audit_info)
        assert config.audited_account == AWS_ACCOUNT_NUMBER

    # Test Config Get Rest APIs
    @mock_config
    def test__describe_configuration_recorder_status__(self):
        # Generate Config Client
        config_client = client("config", region_name=AWS_REGION)
        # Create Config Recorder and start it
        config_client.put_configuration_recorder(
            ConfigurationRecorder={"name": "default", "roleARN": "somearn"}
        )
        # Make the delivery channel
        config_client.put_delivery_channel(
            DeliveryChannel={"name": "testchannel", "s3BucketName": "somebucket"}
        )
        config_client.start_configuration_recorder(ConfigurationRecorderName="default")
        # Config client for this test class
        audit_info = self.set_mocked_audit_info()
        config = Config(audit_info)
        # One recorder per region
        assert len(config.recorders) == 2
        # Check the active one
        # Search for the recorder just created
        for recorder in config.recorders:
            if recorder.name == "default":
                assert recorder.recording is True
