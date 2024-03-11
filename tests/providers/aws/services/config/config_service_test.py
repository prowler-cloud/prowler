from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.config.config_service import Config
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_Config_Service:
    # Test Config Service
    @mock_aws
    def test_service(self):
        # Config client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        config = Config(aws_provider)
        assert config.service == "config"

    # Test Config Client
    @mock_aws
    def test_client(self):
        # Config client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        config = Config(aws_provider)
        for regional_client in config.regional_clients.values():
            assert regional_client.__class__.__name__ == "ConfigService"

    # Test Config Session
    @mock_aws
    def test__get_session__(self):
        # Config client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        config = Config(aws_provider)
        assert config.session.__class__.__name__ == "Session"

    # Test Config Session
    @mock_aws
    def test_audited_account(self):
        # Config client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        config = Config(aws_provider)
        assert config.audited_account == AWS_ACCOUNT_NUMBER

    # Test Config Get Rest APIs
    @mock_aws
    def test__describe_configuration_recorder_status__(self):
        # Generate Config Client
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
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
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        config = Config(aws_provider)
        # One recorder per region
        assert len(config.recorders) == 2
        # Check the active one
        # Search for the recorder just created
        for recorder in config.recorders:
            if recorder.name == "default":
                assert recorder.recording is True
