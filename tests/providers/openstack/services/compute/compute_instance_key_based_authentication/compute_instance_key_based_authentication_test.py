"""Tests for compute_instance_key_based_authentication check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_key_based_authentication:
    """Test suite for compute_instance_key_based_authentication check."""

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
                "prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication import (
                compute_instance_key_based_authentication,
            )

            check = compute_instance_key_based_authentication()
            result = check.execute()

            assert len(result) == 0

    def test_instance_with_keypair(self):
        """Test instance with SSH keypair configured (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="Secure Instance",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="my-production-keypair",
                user_id="user-123",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="10.0.0.5",
                private_v6="",
                networks={"private": ["10.0.0.5"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication import (
                compute_instance_key_based_authentication,
            )

            check = compute_instance_key_based_authentication()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance Secure Instance (instance-1) is configured with SSH key-based authentication (keypair: my-production-keypair)."
            )
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "Secure Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_without_keypair(self):
        """Test instance without SSH keypair (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Insecure Instance",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="user-456",
                access_ipv4="",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="10.0.0.10",
                private_v6="",
                networks={"private": ["10.0.0.10"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication import (
                compute_instance_key_based_authentication,
            )

            check = compute_instance_key_based_authentication()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance Insecure Instance (instance-2) does not have SSH key-based authentication configured (no keypair assigned)."
            )
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Insecure Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_instances_mixed(self):
        """Test multiple instances with mixed keypair configuration."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-secure",
                name="With Key",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=[],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="prod-keypair",
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
                id="instance-insecure",
                name="Without Key",
                status="ACTIVE",
                flavor_id="flavor-1",
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
                "prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_key_based_authentication.compute_instance_key_based_authentication import (
                compute_instance_key_based_authentication,
            )

            check = compute_instance_key_based_authentication()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
