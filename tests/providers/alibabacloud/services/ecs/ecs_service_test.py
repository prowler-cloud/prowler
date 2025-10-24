from unittest import mock
from unittest.mock import MagicMock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ECS_Service:
    def test_ecs_service(self):
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                Disk,
                Instance,
                SecurityGroup,
            )

            ecs_client = MagicMock()

            # Mock instances
            instance_id = "i-test123"
            instance_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:instance/{instance_id}"

            ecs_client.instances = {
                instance_arn: Instance(
                    id=instance_id,
                    name="test-instance",
                    arn=instance_arn,
                    region=ALIBABACLOUD_REGION,
                    status="Running",
                    instance_type="ecs.t6-c1m1.large",
                    public_ip="192.0.2.1",
                    private_ip="10.0.1.10",
                    security_groups=["sg-test123"],
                    vpc_id="vpc-test123",
                    zone_id=f"{ALIBABACLOUD_REGION}-a",
                )
            }

            # Mock disks
            disk_id = "d-test456"
            disk_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:disk/{disk_id}"

            ecs_client.disks = {
                disk_arn: Disk(
                    id=disk_id,
                    name="test-disk",
                    arn=disk_arn,
                    region=ALIBABACLOUD_REGION,
                    disk_type="data",
                    category="cloud_essd",
                    size=100,
                    encrypted=True,
                    kms_key_id="kms-key-123",
                    status="In_use",
                    instance_id=instance_id,
                    zone_id=f"{ALIBABACLOUD_REGION}-a",
                )
            }

            # Mock security groups
            sg_id = "sg-test789"
            sg_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:security-group/{sg_id}"

            ecs_client.security_groups = {
                sg_arn: SecurityGroup(
                    id=sg_id,
                    name="test-sg",
                    arn=sg_arn,
                    region=ALIBABACLOUD_REGION,
                    vpc_id="vpc-test123",
                    description="Test security group",
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

            # Assertions
            assert len(ecs_client.instances) == 1
            assert ecs_client.instances[instance_arn].id == instance_id
            assert ecs_client.instances[instance_arn].name == "test-instance"
            assert ecs_client.instances[instance_arn].region == ALIBABACLOUD_REGION
            assert ecs_client.instances[instance_arn].status == "Running"
            assert ecs_client.instances[instance_arn].public_ip == "192.0.2.1"

            assert len(ecs_client.disks) == 1
            assert ecs_client.disks[disk_arn].id == disk_id
            assert ecs_client.disks[disk_arn].encrypted is True
            assert ecs_client.disks[disk_arn].kms_key_id == "kms-key-123"

            assert len(ecs_client.security_groups) == 1
            assert ecs_client.security_groups[sg_arn].id == sg_id
            assert ecs_client.security_groups[sg_arn].vpc_id == "vpc-test123"
            assert len(ecs_client.security_groups[sg_arn].rules) == 1
