from unittest import mock

import botocore
import botocore.client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_public_snapshot(self, operation_name, kwarg):
    if operation_name == "ModifyDBClusterSnapshotAttribute":
        return {
            "DBClusterSnapshotAttributesResult": {
                "DBClusterSnapshotAttributes": [
                    {
                        "AttributeName": "restore",
                        "DBClusterSnapshotIdentifier": "test-snapshot",
                        "AttributeValues": [],
                    }
                ]
            }
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_public_snapshot_error(self, operation_name, kwarg):
    if operation_name == "ModifyDBClusterSnapshotAttribute":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "DBClusterSnapshotNotFoundFault",
                    "Message": "DBClusterSnapshotNotFoundFault",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_documentdb_cluster_public_snapshot_fixer:
    @mock_aws
    def test_documentdb_cluster_public_snapshot_fixer(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_snapshot,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_service import (
                DocumentDB,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot_fixer.documentdb_client",
                new=DocumentDB(aws_provider),
            ):
                from prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot_fixer import (
                    fixer,
                )

                assert fixer(resource_id="test-snapshot", region=AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_documentdb_cluster_public_snapshot_fixer_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_snapshot_error,
        ):
            from prowler.providers.aws.services.documentdb.documentdb_service import (
                DocumentDB,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot_fixer.documentdb_client",
                new=DocumentDB(aws_provider),
            ):
                from prowler.providers.aws.services.documentdb.documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot_fixer import (
                    fixer,
                )

                assert not fixer(
                    resource_id="test-snapshot", region=AWS_REGION_EU_WEST_1
                )
