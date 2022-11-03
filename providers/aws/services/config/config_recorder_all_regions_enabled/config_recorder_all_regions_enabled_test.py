from unittest import mock

from boto3 import client
from moto import mock_config

AWS_REGION = "us-east-1"


class Test_config_recorder_all_regions_enabled:
    @mock_config
    def test_config_no_recorders(self):
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.config.config_service import Config

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()

            assert (
                len(result) == 23
            )  # One fail result per region, since there are no recorders
            assert result[0].status == "FAIL"

    @mock_config
    def test_config_one_recoder_disabled(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={"name": "default", "roleARN": "somearn"}
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.config.config_service import Config

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()
            assert len(result) == 23
            # Search for the recorder just created
            for recorder in result:
                if recorder.resource_id:
                    assert recorder.status == "FAIL"
                    assert (
                        recorder.status_extended
                        == f"AWS Config recorder default is disabled."
                    )
                    assert recorder.resource_id == "default"

    @mock_config
    def test_config_one_recoder_enabled(self):
        # Create Config Mocked Resources
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
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.config.config_service import Config

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()
            assert len(result) == 23
            # Search for the recorder just created
            for recorder in result:
                if recorder.resource_id:
                    assert recorder.status == "PASS"
                    assert (
                        recorder.status_extended
                        == f"AWS Config recorder default is enabled."
                    )
                    assert recorder.resource_id == "default"
