from unittest import mock

from prowler.providers.aws.services.memorydb.memorydb_service import Cluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

CLUSTER_NAME = "db-cluster-1"
memorydb_arn = f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{CLUSTER_NAME}"

CHECK_PATH = "prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled.memorydb_client"


def build_cluster(tls_enabled: bool) -> Cluster:
    return Cluster(
        name=CLUSTER_NAME,
        arn=memorydb_arn,
        number_of_shards=2,
        engine="valkey",
        engine_version="7.2",
        engine_patch_version="7.2.4",
        multi_az="multiaz",
        region=AWS_REGION_US_EAST_1,
        security_groups=["sg-0a1434xxxxxc9fae"],
        tls_enabled=tls_enabled,
        auto_minor_version_upgrade=True,
        snapshot_limit=0,
    )


class Test_memorydb_cluster_in_transit_encryption_enabled:
    def test_no_clusters(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {}

        with (
            mock.patch(
                "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
                new=memorydb_client,
            ),
            mock.patch(CHECK_PATH, new=memorydb_client),
        ):
            from prowler.providers.aws.services.memorydb.memorydb_cluster_in_transit_encryption_enabled.memorydb_cluster_in_transit_encryption_enabled import (
                memorydb_cluster_in_transit_encryption_enabled,
            )

            check = memorydb_cluster_in_transit_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_cluster_in_transit_encryption_disabled(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {memorydb_arn: build_cluster(tls_enabled=False)}

        with (
            mock.patch(
                "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
                new=memorydb_client,
            ),
            mock.patch(CHECK_PATH, new=memorydb_client),
        ):
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
            assert result[0].resource_arn == memorydb_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    def test_cluster_in_transit_encryption_enabled(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {memorydb_arn: build_cluster(tls_enabled=True)}

        with (
            mock.patch(
                "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
                new=memorydb_client,
            ),
            mock.patch(CHECK_PATH, new=memorydb_client),
        ):
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
            assert result[0].resource_arn == memorydb_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
