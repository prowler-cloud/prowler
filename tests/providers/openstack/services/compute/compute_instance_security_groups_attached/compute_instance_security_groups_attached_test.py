"""Tests for compute_instance_security_groups_attached check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_security_groups_attached:
    """Test suite for compute_instance_security_groups_attached check."""

    def test_no_instances(self):
        """Test when no instances exist."""
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached.compute_client",  # noqa: E501
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached import (  # noqa: E501
                compute_instance_security_groups_attached,
            )

            check = compute_instance_security_groups_attached()
            result = check.execute()

            assert len(result) == 0

    def test_instance_with_security_groups(self):
        """Test instance with security groups attached (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="Instance One",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default", "web"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached.compute_client",  # noqa: E501
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached import (  # noqa: E501
                compute_instance_security_groups_attached,
            )

            check = compute_instance_security_groups_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance Instance One (instance-1) has security groups attached: default, web."
            )
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "Instance One"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_without_security_groups(self):
        """Test instance without security groups attached (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Instance Two",
                status="ACTIVE",
                flavor_id="flavor-2",
                security_groups=[],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached.compute_client",  # noqa: E501
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached import (  # noqa: E501
                compute_instance_security_groups_attached,
            )

            check = compute_instance_security_groups_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance Instance Two (instance-2) does not have any security groups attached."
            )
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Instance Two"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_instances_mixed(self):
        """Test multiple instances with mixed results."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-pass",
                name="Instance Pass",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            ),
            ComputeInstance(
                id="instance-fail",
                name="Instance Fail",
                status="ACTIVE",
                flavor_id="flavor-2",
                security_groups=[],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached.compute_client",  # noqa: E501
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached import (  # noqa: E501
                compute_instance_security_groups_attached,
            )

            check = compute_instance_security_groups_attached()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1

    def test_instance_without_name_uses_id(self):
        """Test instance without name still reports using its ID."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-3",
                name="",
                status="ACTIVE",
                flavor_id="flavor-3",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached.compute_client",  # noqa: E501
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_security_groups_attached.compute_instance_security_groups_attached import (  # noqa: E501
                compute_instance_security_groups_attached,
            )

            check = compute_instance_security_groups_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance  (instance-3) has security groups attached: default."
            )
            assert result[0].resource_id == "instance-3"
            assert result[0].resource_name == ""
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID
