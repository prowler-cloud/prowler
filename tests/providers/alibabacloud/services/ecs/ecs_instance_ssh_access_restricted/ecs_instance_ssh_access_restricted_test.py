from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ecs_instance_ssh_access_restricted:
    def test_no_security_groups(self):
        ecs_client = mock.MagicMock
        ecs_client.security_groups = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted import (
                ecs_instance_ssh_access_restricted,
            )

            check = ecs_instance_ssh_access_restricted()
            result = check.execute()
            assert len(result) == 0

    def test_ssh_access_restricted(self):
        ecs_client = mock.MagicMock
        sg_id = "sg-test123"
        sg_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:security-group/{sg_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted import (
                ecs_instance_ssh_access_restricted,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            ecs_client.security_groups = {
                sg_arn: SecurityGroup(
                    id=sg_id,
                    name="restricted-sg",
                    arn=sg_arn,
                    region=ALIBABACLOUD_REGION,
                    vpc_id="vpc-test123",
                    description="Restricted security group",
                    rules=[
                        {
                            "direction": "ingress",
                            "protocol": "tcp",
                            "port_range": "22/22",
                            "source": "10.0.0.0/8",
                        }
                    ],
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_instance_ssh_access_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == sg_id
            assert result[0].resource_arn == sg_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "does not allow unrestricted SSH access" in result[0].status_extended

    def test_ssh_access_unrestricted(self):
        ecs_client = mock.MagicMock
        sg_id = "sg-test456"
        sg_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:security-group/{sg_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_ssh_access_restricted.ecs_instance_ssh_access_restricted import (
                ecs_instance_ssh_access_restricted,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            ecs_client.security_groups = {
                sg_arn: SecurityGroup(
                    id=sg_id,
                    name="unrestricted-sg",
                    arn=sg_arn,
                    region=ALIBABACLOUD_REGION,
                    vpc_id="vpc-test123",
                    description="Unrestricted security group",
                    rules=[
                        {
                            "direction": "ingress",
                            "protocol": "tcp",
                            "port_range": "22/22",
                            "source": "0.0.0.0/0",
                        }
                    ],
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_instance_ssh_access_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sg_id
            assert result[0].resource_arn == sg_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "allows unrestricted SSH access" in result[0].status_extended
