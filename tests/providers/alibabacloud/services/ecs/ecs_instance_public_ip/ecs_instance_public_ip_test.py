from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ecs_instance_public_ip:
    def test_no_instances(self):
        ecs_client = mock.MagicMock
        ecs_client.instances = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )

            check = ecs_instance_public_ip()
            result = check.execute()
            assert len(result) == 0

    def test_instance_no_public_ip(self):
        ecs_client = mock.MagicMock
        instance_id = "i-test123"
        instance_arn = (
            f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:instance/{instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                Instance,
            )

            ecs_client.instances = {
                instance_arn: Instance(
                    id=instance_id,
                    name="private-instance",
                    arn=instance_arn,
                    region=ALIBABACLOUD_REGION,
                    status="Running",
                    public_ip=None,
                    private_ip="10.0.1.10",
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance_id
            assert "does not have a public IP" in result[0].status_extended

    def test_instance_with_public_ip(self):
        ecs_client = mock.MagicMock
        instance_id = "i-test456"
        instance_arn = (
            f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:instance/{instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                Instance,
            )

            ecs_client.instances = {
                instance_arn: Instance(
                    id=instance_id,
                    name="public-instance",
                    arn=instance_arn,
                    region=ALIBABACLOUD_REGION,
                    status="Running",
                    public_ip="203.0.113.1",
                    private_ip="10.0.1.10",
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance_id
            assert "has a public IP address" in result[0].status_extended
            assert "203.0.113.1" in result[0].status_extended
