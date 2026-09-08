from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CLUSTER_NAME = "db-cluster-1"
CLUSTER_ARN = f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{CLUSTER_NAME}"

CHECK_PATH = "prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled.memorydb_client"
PROVIDER_PATH = "prowler.providers.common.provider.Provider.get_global_provider"

make_api_call = botocore.client.BaseClient._make_api_call


def cluster_payload(tls_enabled: bool) -> dict:
    return {
        "Name": CLUSTER_NAME,
        "Status": "available",
        "NumberOfShards": 2,
        "AvailabilityMode": "multiaz",
        "Engine": "valkey",
        "EngineVersion": "7.2",
        "EnginePatchVersion": "7.2.4",
        "SecurityGroups": [
            {"SecurityGroupId": "sg-0a1434xxxxxc9fae", "Status": "active"}
        ],
        "TLSEnabled": tls_enabled,
        "ARN": CLUSTER_ARN,
        "SnapshotRetentionLimit": 0,
        "AutoMinorVersionUpgrade": True,
    }


def mock_describe_clusters(clusters: list):
    """Stub DescribeClusters, which moto covers only partially.

    Moto accepts ``Engine`` on CreateCluster but never returns it from
    DescribeClusters, and the service layer requires that field, so every
    cluster would be dropped before reaching the check.
    """

    def mock_make_api_call(self, operation_name, kwargs):
        if operation_name == "DescribeClusters":
            return {"Clusters": clusters}
        return make_api_call(self, operation_name, kwargs)

    return mock_make_api_call


def build_memorydb_client(clusters: list):
    from prowler.providers.aws.services.memorydb.memorydb_service import MemoryDB

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_describe_clusters(clusters),
    ):
        return aws_provider, MemoryDB(aws_provider)


class Test_memorydb_cluster_in_transit_encryption_enabled:
    @mock_aws
    def test_no_clusters(self):
        aws_provider, memorydb_client = build_memorydb_client([])

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=memorydb_client):
                from prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled import (
                    memorydb_cluster_in_transit_encryption_enabled,
                )

                check = memorydb_cluster_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_cluster_in_transit_encryption_disabled(self):
        aws_provider, memorydb_client = build_memorydb_client(
            [cluster_payload(tls_enabled=False)]
        )

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=memorydb_client):
                from prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled import (
                    memorydb_cluster_in_transit_encryption_enabled,
                )

                check = memorydb_cluster_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Memory DB Cluster {CLUSTER_NAME} does not have in-transit encryption enabled."
                )
                assert result[0].resource_id == CLUSTER_NAME
                assert result[0].resource_arn == CLUSTER_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_cluster_in_transit_encryption_enabled(self):
        aws_provider, memorydb_client = build_memorydb_client(
            [cluster_payload(tls_enabled=True)]
        )

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=memorydb_client):
                from prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled import (
                    memorydb_cluster_in_transit_encryption_enabled,
                )

                check = memorydb_cluster_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Memory DB Cluster {CLUSTER_NAME} has in-transit encryption enabled."
                )
                assert result[0].resource_id == CLUSTER_NAME
                assert result[0].resource_arn == CLUSTER_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
