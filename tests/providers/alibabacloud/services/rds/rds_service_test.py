from unittest.mock import patch
from prowler.providers.alibabacloud.services.rds.rds_service import RDS, DBInstance
from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_RDS_Service:
    def test_service(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ):
            rds = RDS(set_mocked_alibabacloud_provider())

            assert rds.service == "rds"
            assert rds.account_id == ALIBABACLOUD_ACCOUNT_ID
            assert rds.region == ALIBABACLOUD_REGION
            assert len(rds.regions) > 0

    def test_db_instance_creation(self):
        db_instance_id = "rm-test123"
        arn = f"acs:rds:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:dbinstance/{db_instance_id}"

        db_instance = DBInstance(
            db_instance_id=db_instance_id,
            db_instance_name="test-db",
            arn=arn,
            region=ALIBABACLOUD_REGION,
            engine="MySQL",
            engine_version="8.0",
            public_access=False,
            encryption_enabled=True,
            backup_retention_period=14,
            ssl_enabled=True,
            multi_az=True,
            auto_minor_version_upgrade=True,
            deletion_protection=True,
            audit_log_enabled=True,
            vpc_id="vpc-test123",
            security_ips=["192.168.0.0/16"],
        )

        assert db_instance.db_instance_id == db_instance_id
        assert db_instance.db_instance_name == "test-db"
        assert db_instance.arn == arn
        assert db_instance.region == ALIBABACLOUD_REGION
        assert db_instance.engine == "MySQL"
        assert db_instance.engine_version == "8.0"
        assert db_instance.public_access is False
        assert db_instance.encryption_enabled is True
        assert db_instance.backup_retention_period == 14
        assert db_instance.ssl_enabled is True
        assert db_instance.multi_az is True
        assert db_instance.auto_minor_version_upgrade is True
        assert db_instance.deletion_protection is True
        assert db_instance.audit_log_enabled is True
        assert db_instance.vpc_id == "vpc-test123"
        assert db_instance.security_ips == ["192.168.0.0/16"]

    def test_db_instance_default_security_ips(self):
        db_instance = DBInstance(
            db_instance_id="rm-test",
            db_instance_name="test-db",
            arn="arn",
            region=ALIBABACLOUD_REGION,
        )

        assert db_instance.security_ips == ["0.0.0.0/0"]
