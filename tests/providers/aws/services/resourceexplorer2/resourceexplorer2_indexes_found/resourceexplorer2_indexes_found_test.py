from unittest import mock

from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service import (
    Indexes,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

INDEX_ARN = "arn:aws:resource-explorer-2:ap-south-1:123456789012:index/123456-2896-4fe8-93d2-15ec137e5c47"
INDEX_REGION = "us-east-1"


class Test_resourceexplorer2_indexes_found:
    def test_no_indexes_found(self):
        resourceexplorer2_client = mock.MagicMock
        resourceexplorer2_client.indexes = []
        resourceexplorer2_client.audited_account = AWS_ACCOUNT_NUMBER
        resourceexplorer2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        resourceexplorer2_client.audited_partition = "aws"
        resourceexplorer2_client.region = AWS_REGION_US_EAST_1
        resourceexplorer2_client.index_arn_template = f"arn:{resourceexplorer2_client.audited_partition}:resource-explorer:{resourceexplorer2_client.region}:{resourceexplorer2_client.audited_account}:index"
        resourceexplorer2_client.__get_index_arn_template__ = mock.MagicMock(
            return_value=resourceexplorer2_client.index_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service.ResourceExplorer2",
            new=resourceexplorer2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_indexes_found.resourceexplorer2_indexes_found import (
                resourceexplorer2_indexes_found,
            )

            check = resourceexplorer2_indexes_found()
            result = check.execute()

            # Assertions
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No Resource Explorer Indexes found."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:resource-explorer:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:index"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_one_index_found(self):
        resourceexplorer2_client = mock.MagicMock
        resourceexplorer2_client.indexes = [
            Indexes(arn=INDEX_ARN, region=INDEX_REGION, type="LOCAL")
        ]
        resourceexplorer2_client.audited_account = AWS_ACCOUNT_NUMBER
        resourceexplorer2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        resourceexplorer2_client.region = AWS_REGION_US_EAST_1
        resourceexplorer2_client.audited_partition = "aws"
        resourceexplorer2_client.index_arn_template = f"arn:{resourceexplorer2_client.audited_partition}:resource-explorer:{resourceexplorer2_client.region}:{resourceexplorer2_client.audited_account}:index"
        resourceexplorer2_client.__get_index_arn_template__ = mock.MagicMock(
            return_value=resourceexplorer2_client.index_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service.ResourceExplorer2",
            new=resourceexplorer2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_indexes_found.resourceexplorer2_indexes_found import (
                resourceexplorer2_indexes_found,
            )

            check = resourceexplorer2_indexes_found()
            result = check.execute()

            # Assertions
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Resource Explorer Indexes found: 1."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == INDEX_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
