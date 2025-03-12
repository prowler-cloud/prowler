from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

ATHENA_PRIMARY_WORKGROUP = "primary"
ATHENA_PRIMARY_WORKGROUP_ARN = f"arn:aws:athena:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workgroup/{ATHENA_PRIMARY_WORKGROUP}"


class Test_athena_workgroup_logging_enabled:
    @mock_aws
    def test_primary_workgroup_logging_disabled(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled import (
                athena_workgroup_logging_enabled,
            )

            check = athena_workgroup_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} does not have CloudWatch logging enabled."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_primary_workgroup_logging_disabled_ignoring(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._scan_unused_services = False

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled import (
                athena_workgroup_logging_enabled,
            )

            check = athena_workgroup_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_primary_workgroup_logging_enabled(self):
        athena_client = client("athena", region_name=AWS_REGION_EU_WEST_1)

        # Delete and recreate the primary workgroup with logging enabled
        athena_client.delete_work_group(WorkGroup=ATHENA_PRIMARY_WORKGROUP)

        athena_client.create_work_group(
            Name=ATHENA_PRIMARY_WORKGROUP,
            Configuration={
                "ResultConfiguration": {
                    "OutputLocation": f"s3://aws-athena-query-results-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}/",
                    "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"},
                },
                "EnforceWorkGroupConfiguration": False,
                "PublishCloudWatchMetricsEnabled": True,
                "BytesScannedCutoffPerQuery": 100000000,
                "RequesterPaysEnabled": False,
                "EngineVersion": {
                    "SelectedEngineVersion": "Athena engine version 2",
                    "EffectiveEngineVersion": "Athena engine version 2",
                },
            },
            Description="Primary WorkGroup",
        )

        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_logging_enabled.athena_workgroup_logging_enabled import (
                athena_workgroup_logging_enabled,
            )

            check = athena_workgroup_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} has CloudWatch logging enabled."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
