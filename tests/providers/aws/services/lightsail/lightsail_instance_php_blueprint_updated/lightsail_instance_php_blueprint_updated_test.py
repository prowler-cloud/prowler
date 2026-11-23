from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.aws.services.lightsail.lightsail_service import Instance
from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    BASE_LIGHTSAIL_ARN,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.lightsail.lightsail_instance_php_blueprint_updated.lightsail_instance_php_blueprint_updated"
INSTANCE_ARN = f"{BASE_LIGHTSAIL_ARN}:Instance/test-instance"


def _instance(blueprint_id, blueprint_name=""):
    return Instance(
        name="test-instance",
        id="1234/5678",
        arn=INSTANCE_ARN,
        tags=[],
        region=AWS_REGION_US_EAST_1,
        availability_zone=AWS_REGION_US_EAST_1_AZA,
        static_ip=False,
        public_ip="",
        private_ip="172.16.2.3",
        ipv6_addresses=[],
        ip_address_type="ipv4",
        ports=[],
        auto_snapshot=False,
        blueprint_id=blueprint_id,
        blueprint_name=blueprint_name,
    )


def _run_check(instances, audit_config=None):
    lightsail_client = MagicMock
    lightsail_client.instances = instances
    lightsail_client.audit_config = audit_config or {}

    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        patch(
            "prowler.providers.aws.services.lightsail.lightsail_service.Lightsail",
            new=lightsail_client,
        ),
        patch(f"{CHECK_PATH}.lightsail_client", new=lightsail_client),
    ):
        from prowler.providers.aws.services.lightsail.lightsail_instance_php_blueprint_updated.lightsail_instance_php_blueprint_updated import (
            lightsail_instance_php_blueprint_updated,
        )

        return lightsail_instance_php_blueprint_updated().execute()


class Test_lightsail_instance_php_blueprint_updated:
    def test_no_instances(self):
        assert len(_run_check({})) == 0

    @pytest.mark.parametrize("blueprint_id", ["ubuntu_22_04", "nodejs", "mean", ""])
    def test_non_php_blueprint_is_skipped(self, blueprint_id):
        assert len(_run_check({INSTANCE_ARN: _instance(blueprint_id)})) == 0

    @pytest.mark.parametrize(
        "blueprint_id",
        ["wordpress", "wordpress_multisite", "lamp_8_bitnami", "nginx", "drupal"],
    )
    def test_php_blueprint_is_manual(self, blueprint_id):
        result = _run_check({INSTANCE_ARN: _instance(blueprint_id, "WordPress")})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Lightsail instance test-instance was created from the PHP blueprint '{blueprint_id}'; the PHP runtime cannot be inspected through the API, verify over SSH that it runs a fixed release (8.2.35, 8.3.36, 8.4.27, 8.5.12 or newer); Bitnami-packaged blueprints bundle a PHP copy that apt never updates, so migrate them to the Lightsail-packaged blueprint or replace the bundled PHP with a package-managed one."
        )
        assert result[0].resource_id == "1234/5678"
        assert result[0].resource_arn == INSTANCE_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_custom_blueprint_list(self):
        instances = {INSTANCE_ARN: _instance("custom_php_app")}
        assert len(_run_check(instances)) == 0
        result = _run_check(instances, {"lightsail_php_blueprints": ["custom_php"]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
