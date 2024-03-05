from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_SOUTH_2,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_config_recorder_all_regions_enabled:
    @mock_aws
    def test_config_no_recorders(self):
        from prowler.providers.aws.services.config.config_service import Config

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()

            assert (
                len(result) == 2
            )  # One fail result per region, since there are no recorders
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS Config recorder {AWS_ACCOUNT_NUMBER} is disabled."
            )
            assert (
                result[0].resource_arn
                == f"arn:aws:config:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"AWS Config recorder {AWS_ACCOUNT_NUMBER} is disabled."
            )
            assert (
                result[1].resource_arn
                == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
            )
            assert result[1].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_config_one_recoder_disabled(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={"name": "default", "roleARN": "somearn"}
        )
        from prowler.providers.aws.services.config.config_service import Config

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()
            assert len(result) == 1
            # Search for the recorder just created
            for recorder in result:
                if recorder.resource_id:
                    assert recorder.status == "FAIL"
                    assert (
                        recorder.status_extended
                        == "AWS Config recorder default is disabled."
                    )
                    assert recorder.resource_id == "default"
                    assert (
                        recorder.resource_arn
                        == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
                    )
                    assert recorder.region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_config_one_recoder_enabled(self):
        # Create Config Mocked Resources
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
        from prowler.providers.aws.services.config.config_service import Config

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()
            assert len(result) == 1
            # Search for the recorder just created
            for recorder in result:
                if recorder.resource_id:
                    assert recorder.status == "PASS"
                    assert (
                        recorder.status_extended
                        == "AWS Config recorder default is enabled."
                    )
                    assert recorder.resource_id == "default"
                    assert (
                        recorder.resource_arn
                        == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
                    )
                    assert recorder.region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_config_one_recorder_disabled_allowlisted(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={"name": AWS_ACCOUNT_NUMBER, "roleARN": "somearn"}
        )
        from prowler.providers.aws.services.config.config_service import Config

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_SOUTH_2, AWS_REGION_US_EAST_1],
            profile_region=AWS_REGION_EU_SOUTH_2,
            audit_config={"allowlist_non_default_regions": True},
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled.config_client",
            new=Config(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import (
                config_recorder_all_regions_enabled,
            )

            check = config_recorder_all_regions_enabled()
            result = check.execute()
            assert len(result) == 2
            # Search for the recorder just created
            for recorder in result:
                if recorder.region == AWS_REGION_US_EAST_1:
                    assert recorder.status == "WARNING"
                    assert (
                        recorder.status_extended
                        == f"AWS Config recorder {AWS_ACCOUNT_NUMBER} is disabled."
                    )
                    assert recorder.resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        recorder.resource_arn
                        == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
                    )
                    assert recorder.region == AWS_REGION_US_EAST_1
                else:
                    assert recorder.status == "FAIL"
                    assert (
                        recorder.status_extended
                        == f"AWS Config recorder {AWS_ACCOUNT_NUMBER} is disabled."
                    )
                    assert recorder.resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        recorder.resource_arn
                        == f"arn:aws:config:{AWS_REGION_EU_SOUTH_2}:{AWS_ACCOUNT_NUMBER}:recorder"
                    )
                    assert recorder.region == AWS_REGION_EU_SOUTH_2
