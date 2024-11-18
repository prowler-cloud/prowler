from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_guardduty_is_enabled:
    @mock_aws
    def test_no_detectors(self):
        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ) as guardduty_client:
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            guardduty_client.detectors = []

            check = guardduty_is_enabled()
            results = check.execute()
            assert len(results) == 0

    @mock_aws
    def test_guardduty_enabled(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=True)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            check = guardduty_is_enabled()
            results = check.execute()
            assert len(results) == 29
            for result in results:
                if result.region == AWS_REGION_EU_WEST_1:
                    assert result.status == "PASS"
                    assert (
                        result.status_extended
                        == f"GuardDuty detector {result.resource_id} enabled."
                    )
                    assert result.resource_id == detector_id
                    assert (
                        result.resource_arn
                        == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                    )
                    assert result.resource_tags == []

    @mock_aws
    def test_guardduty_configured_but_suspended(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=False)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ) as mock_guardduty_client:
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            for detector in mock_guardduty_client.detectors:
                if detector.region == AWS_REGION_EU_WEST_1:
                    detector.status = False

            check = guardduty_is_enabled()
            results = check.execute()
            assert len(results) == 29
            for result in results:
                if result.region == AWS_REGION_EU_WEST_1:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"GuardDuty detector {result.resource_id} configured but suspended."
                    )
                    assert result.resource_id == detector_id
                    assert (
                        result.resource_arn
                        == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                    )
                    assert result.resource_tags == []

    @mock_aws
    def test_guardduty_not_configured(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=False)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ) as mock_guardduty_client:
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            for detector in mock_guardduty_client.detectors:
                if detector.region == AWS_REGION_EU_WEST_1:
                    detector.status = None

            check = guardduty_is_enabled()
            results = check.execute()
            assert len(results) == 29
            for result in results:
                if result.region == AWS_REGION_EU_WEST_1:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"GuardDuty detector {result.resource_id} not configured."
                    )
                    assert result.resource_id == detector_id
                    assert (
                        result.resource_arn
                        == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                    )
                    assert result.resource_tags == []

    @mock_aws
    def test_guardduty_not_configured_muted(self):
        guardduty_client = client("guardduty", region_name=AWS_REGION_EU_WEST_1)

        detector_id = guardduty_client.create_detector(Enable=False)["DetectorId"]

        aws_provider = set_mocked_aws_provider()

        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled.guardduty_client",
            new=GuardDuty(aws_provider),
        ) as mock_guardduty_client:
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            mock_guardduty_client.audit_config = {"mute_non_default_regions": True}

            check = guardduty_is_enabled()
            results = check.execute()
            assert len(results) == 29
            for result in results:
                if result.region == AWS_REGION_EU_WEST_1:
                    assert result.status == "FAIL"
                    assert result.muted
                    assert (
                        result.status_extended
                        == f"GuardDuty detector {result.resource_id} not configured."
                    )
                    assert result.resource_id == detector_id
                    assert (
                        result.resource_arn
                        == f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{detector_id}"
                    )
                    assert result.resource_tags == []
                    assert result.muted
