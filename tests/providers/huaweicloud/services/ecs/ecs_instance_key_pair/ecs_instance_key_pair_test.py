from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEcsInstanceKeyPair:
    def test_instance_with_key_pair_passes(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair import (
                ecs_instance_key_pair,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                key_name="my-keypair",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_key_pair()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "inst-1"
            assert "my-keypair" in result[0].status_extended

    def test_instance_without_key_pair_fails(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair import (
                ecs_instance_key_pair,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                key_name="",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_key_pair()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not use an SSH key pair" in result[0].status_extended

    def test_no_instances(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_key_pair.ecs_instance_key_pair import (
                ecs_instance_key_pair,
            )

            ecs_client.instances = {}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_key_pair()
            result = check.execute()

            assert len(result) == 0
