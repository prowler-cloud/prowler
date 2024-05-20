from unittest import mock

from mock import patch
from moto import mock_aws

from tests.providers.aws.services.athena.athena_service_test import mock_make_api_call
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

ATHENA_PRIMARY_WORKGROUP = "primary"
ATHENA_PRIMARY_WORKGROUP_ARN = f"arn:aws:athena:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workgroup/{ATHENA_PRIMARY_WORKGROUP}"


class Test_athena_workgroup_encryption:
    @mock_aws
    def test_primary_workgroup_not_encrypted(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption import (
                athena_workgroup_encryption,
            )

            check = athena_workgroup_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} does not encrypt the query results."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_primary_workgroup_not_encrypted_ignoring(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._scan_unused_services = False

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption import (
                athena_workgroup_encryption,
            )

            check = athena_workgroup_encryption()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    # We mock the get_work_group to return an encrypted workgroup
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_primary_workgroup_encrypted(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption.athena_client",
            new=Athena(aws_provider),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption import (
                athena_workgroup_encryption,
            )

            check = athena_workgroup_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} encrypts the query results using SSE_S3."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
