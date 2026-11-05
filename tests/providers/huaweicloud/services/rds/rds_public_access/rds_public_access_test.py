from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRdsPublicAccess:
    def test_public_instance_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access import (
                rds_public_access,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="public-db",
                public_ip="1.2.3.4",
                is_public=True,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1.2.3.4" in result[0].status_extended

    def test_private_instance_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access import (
                rds_public_access,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="private-db",
                public_ip="",
                is_public=False,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have a public IP" in result[0].status_extended

    def test_no_instances(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_public_access.rds_public_access import (
                rds_public_access,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            check = rds_public_access()
            result = check.execute()

            assert len(result) == 0
