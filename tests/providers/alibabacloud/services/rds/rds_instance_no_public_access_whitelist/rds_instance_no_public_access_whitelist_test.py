from types import SimpleNamespace
from unittest import mock

from prowler.providers.alibabacloud.services.rds.rds_service import (
    DBInstance,
    security_ips_from_array_item,
)
from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


def _instance(security_ips: list) -> DBInstance:
    return DBInstance(
        id="db-1",
        name="db-1",
        region="cn-hangzhou",
        engine="MySQL",
        engine_version="8.0",
        status="Running",
        type="Primary",
        net_type="VPC",
        connection_mode="Standard",
        public_connection_string="",
        ssl_enabled=True,
        tde_status="Disabled",
        tde_key_id="",
        security_ips=security_ips,
        audit_log_enabled=False,
        audit_log_retention=0,
        log_connections="",
        log_disconnections="",
        log_duration="",
    )


class TestRdsInstanceNoPublicAccessWhitelist:
    def _run(self, instances):
        rds_client = mock.MagicMock()
        rds_client.audited_account = "1234567890"
        rds_client.instances = instances

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.rds.rds_instance_no_public_access_whitelist.rds_instance_no_public_access_whitelist.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_no_public_access_whitelist.rds_instance_no_public_access_whitelist import (
                rds_instance_no_public_access_whitelist,
            )

            return rds_instance_no_public_access_whitelist().execute()

    def test_no_instances(self):
        assert self._run([]) == []

    def test_private_whitelist_passes(self):
        result = self._run([_instance(["10.0.0.0/8", "192.168.1.10"])])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "is not open to the world" in result[0].status_extended

    def test_ipv4_open_whitelist_fails(self):
        result = self._run([_instance(["10.0.0.1", "0.0.0.0/0"])])

        assert result[0].status == "FAIL"
        assert "0.0.0.0/0 allowed" in result[0].status_extended

    def test_bare_ipv4_open_whitelist_fails(self):
        result = self._run([_instance(["0.0.0.0"])])

        assert result[0].status == "FAIL"
        assert "0.0.0.0 allowed" in result[0].status_extended

    def test_ipv6_open_whitelist_fails(self):
        result = self._run([_instance(["10.0.0.1", " ::/0"])])

        assert result[0].status == "FAIL"
        assert "::/0 allowed" in result[0].status_extended
        assert result[0].resource_id == "db-1"
        assert result[0].region == "cn-hangzhou"


def test_security_ips_come_from_the_sdk_iplist_field():
    """The describe response stores the whitelist on security_iplist."""
    item = SimpleNamespace(security_iplist="10.0.0.1,::/0")
    assert security_ips_from_array_item(item) == ["10.0.0.1", "::/0"]
    assert security_ips_from_array_item(SimpleNamespace(security_ips="0.0.0.0/0")) == [
        "0.0.0.0/0"
    ]
