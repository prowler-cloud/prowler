from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.rds.rds_service import RDS, RDSInstance
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock.

    RDS iterates ``self.regional_clients`` in ``_list_instances``, so the
    controlled client is wired through ``generate_regional_clients``.
    """
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestRDSService:
    def test_list_instances_parses(self):
        public_instance = SimpleNamespace(
            id="rds-public",
            name="public-db",
            status="ACTIVE",
            public_ips=["1.2.3.4"],
            backup_strategy=SimpleNamespace(keep_days=7),
            datastore=SimpleNamespace(type="MySQL", version="8.0"),
            disk_encryption_id="kms-key-1",
        )
        private_instance = SimpleNamespace(
            id="rds-private",
            name="private-db",
            status="ACTIVE",
            public_ips=[],
            backup_strategy=SimpleNamespace(keep_days=0),
            datastore=SimpleNamespace(type="PostgreSQL", version="14"),
            disk_encryption_id="",
        )

        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_instances.return_value = SimpleNamespace(
            instances=[public_instance, private_instance]
        )

        rds = RDS(_provider_with_client(regional_client))

        assert len(rds.instances) == 2
        by_id = {inst.id: inst for inst in rds.instances}

        public_db = by_id["rds-public"]
        assert isinstance(public_db, RDSInstance)
        assert public_db.name == "public-db"
        assert public_db.region == REGION
        assert public_db.engine == "MySQL"
        assert public_db.engine_version == "8.0"
        # is_public derives from public_ips list
        assert public_db.is_public is True
        assert public_db.public_ip == "1.2.3.4"
        # backup_enabled derives from backup_strategy.keep_days
        assert public_db.backup_enabled is True
        assert public_db.disk_encryption_id == "kms-key-1"

        private_db = by_id["rds-private"]
        assert private_db.is_public is False
        assert private_db.public_ip == ""
        assert private_db.backup_enabled is False
        assert private_db.engine == "PostgreSQL"
        assert private_db.disk_encryption_id == ""

    def test_list_instances_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_instances.return_value = SimpleNamespace(instances=[])

        rds = RDS(_provider_with_client(regional_client))

        assert rds.instances == []

    def test_list_instances_derives_multi_az_from_distinct_node_zones(self):
        multi_az_instance = SimpleNamespace(
            id="rds-multi-az",
            name="multi-az-db",
            status="ACTIVE",
            public_ips=[],
            backup_strategy=None,
            datastore=None,
            disk_encryption_id="",
            nodes=[
                SimpleNamespace(availability_zone="eu-west-101a"),
                SimpleNamespace(availability_zone="eu-west-101b"),
            ],
        )
        single_az_instance = SimpleNamespace(
            id="rds-single-az",
            name="single-az-db",
            status="ACTIVE",
            public_ips=[],
            backup_strategy=None,
            datastore=None,
            disk_encryption_id="",
            nodes=[
                SimpleNamespace(availability_zone="eu-west-101a"),
                SimpleNamespace(availability_zone="eu-west-101a"),
            ],
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_instances.return_value = SimpleNamespace(
            instances=[multi_az_instance, single_az_instance]
        )

        rds = RDS(_provider_with_client(regional_client))

        by_id = {instance.id: instance for instance in rds.instances}
        assert by_id["rds-multi-az"].is_multi_az is True
        assert by_id["rds-single-az"].is_multi_az is False

    def test_list_instances_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_instances.side_effect = Exception("boom")

        rds = RDS(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert rds.instances == []
