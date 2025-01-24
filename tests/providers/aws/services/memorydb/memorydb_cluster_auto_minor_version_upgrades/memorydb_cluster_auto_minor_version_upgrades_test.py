from unittest import mock

from prowler.providers.aws.services.memorydb.memorydb_service import Cluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

memorydb_arn = (
    f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
)


class Test_memorydb_cluster_auto_minor_version_upgrades:
    def test_no_memorydb(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {}

        with mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
            new=memorydb_client,
        ), mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades.memorydb_client",
            new=memorydb_client,
        ):
            from prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades import (
                memorydb_cluster_auto_minor_version_upgrades,
            )

            check = memorydb_cluster_auto_minor_version_upgrades()
            result = check.execute()

            assert len(result) == 0

    def test_memorydb_no_minor(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {}
        memorydb_client.clusters = {
            "db-cluster-1": Cluster(
                name="db-cluster-1",
                arn=memorydb_arn,
                status="available",
                number_of_shards=2,
                engine="valkey",
                engine_version="6.2",
                region=AWS_REGION_US_EAST_1,
                engine_patch_version="6.2.6",
                multi_az=True,
                SecurityGroups=[
                    {"SecurityGroupId": "sg-0a1434xxxxxc9fae", "Status": "active"}
                ],
                tls_enabled=False,
                snapshot_limit=0,
                auto_minor_version_upgrade=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
            new=memorydb_client,
        ), mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades.memorydb_client",
            new=memorydb_client,
        ):
            from prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades import (
                memorydb_cluster_auto_minor_version_upgrades,
            )

            check = memorydb_cluster_auto_minor_version_upgrades()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Memory DB Cluster db-cluster-1 does not have minor version upgrade enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []

    def test_memorydb_minor_enabled(self):
        memorydb_client = mock.MagicMock
        memorydb_client.clusters = {}
        memorydb_client.clusters = {
            "db-cluster-1": Cluster(
                name="db-cluster-1",
                arn=memorydb_arn,
                status="available",
                number_of_shards=2,
                engine="valkey",
                engine_version="6.2",
                region=AWS_REGION_US_EAST_1,
                engine_patch_version="6.2.6",
                multi_az=True,
                SecurityGroups=[
                    {"SecurityGroupId": "sg-0a1434xxxxxc9fae", "Status": "active"}
                ],
                tls_enabled=False,
                snapshot_limit=0,
                auto_minor_version_upgrade=True,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_service.MemoryDB",
            new=memorydb_client,
        ), mock.patch(
            "prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades.memorydb_client",
            new=memorydb_client,
        ):
            from prowler.providers.aws.services.memorydb.memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades import (
                memorydb_cluster_auto_minor_version_upgrades,
            )

            check = memorydb_cluster_auto_minor_version_upgrades()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Memory DB Cluster db-cluster-1 has minor version upgrade enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []
