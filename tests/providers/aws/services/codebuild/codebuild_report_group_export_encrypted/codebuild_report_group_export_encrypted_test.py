from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call_encrypted(self, operation_name, kwarg):
    if operation_name == "ListReportGroups":
        return {
            "reportGroups": [
                f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-encrypted"
            ]
        }
    elif operation_name == "BatchGetReportGroups":
        return {
            "reportGroups": [
                {
                    "name": "test-report-group-encrypted",
                    "arn": f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-encrypted",
                    "exportConfig": {
                        "exportConfigType": "S3",
                        "s3Destination": {
                            "bucket": "test-bucket",
                            "path": "test-path",
                            "encryptionKey": f"arn:aws:kms:eu-west-1:{AWS_ACCOUNT_NUMBER}:key/12345678-1234-1234-1234-{AWS_ACCOUNT_NUMBER}",
                            "encryptionDisabled": False,
                        },
                    },
                    "tags": [{"key": "Name", "value": "test-report-group-encrypted"}],
                    "status": "ACTIVE",
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_not_encrypted(self, operation_name, kwarg):
    if operation_name == "ListReportGroups":
        return {
            "reportGroups": [
                f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-not-encrypted"
            ]
        }
    elif operation_name == "BatchGetReportGroups":
        return {
            "reportGroups": [
                {
                    "name": "test-report-group-not-encrypted",
                    "arn": f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-not-encrypted",
                    "exportConfig": {
                        "exportConfigType": "S3",
                        "s3Destination": {
                            "bucket": "test-bucket",
                            "path": "test-path",
                            "encryptionKey": "",
                            "encryptionDisabled": True,
                        },
                    },
                    "tags": [
                        {"key": "Name", "value": "test-report-group-not-encrypted"}
                    ],
                    "status": "ACTIVE",
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_codebuild_report_group_export_encrypted:
    @mock_aws
    def test_no_report_groups(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted import (
                codebuild_report_group_export_encrypted,
            )

            check = codebuild_report_group_export_encrypted()
            result = check.execute()

            assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_encrypted
    )
    @mock_aws
    def test_report_group_export_encrypted(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted import (
                codebuild_report_group_export_encrypted,
            )

            check = codebuild_report_group_export_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild report group test-report-group-encrypted exports are encrypted at s3://test-bucket/test-path with KMS key arn:aws:kms:eu-west-1:{AWS_ACCOUNT_NUMBER}:key/12345678-1234-1234-1234-{AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == "test-report-group-encrypted"
            assert (
                result[0].resource_arn
                == f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-encrypted"
            )
            assert result[0].resource_tags == [
                {"key": "Name", "value": "test-report-group-encrypted"}
            ]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_not_encrypted,
    )
    @mock_aws
    def test_report_group_export_not_encrypted(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_report_group_export_encrypted.codebuild_report_group_export_encrypted import (
                codebuild_report_group_export_encrypted,
            )

            check = codebuild_report_group_export_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CodeBuild report group test-report-group-not-encrypted exports are not encrypted at s3://test-bucket/test-path."
            )
            assert result[0].resource_id == "test-report-group-not-encrypted"
            assert (
                result[0].resource_arn
                == f"arn:aws:codebuild:eu-west-1:{AWS_ACCOUNT_NUMBER}:report-group/test-report-group-not-encrypted"
            )
            assert result[0].resource_tags == [
                {"key": "Name", "value": "test-report-group-not-encrypted"}
            ]
            assert result[0].region == AWS_REGION_EU_WEST_1
