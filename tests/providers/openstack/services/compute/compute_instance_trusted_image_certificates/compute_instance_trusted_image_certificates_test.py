"""Tests for compute_instance_trusted_image_certificates check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_trusted_image_certificates:
    """Test suite for compute_instance_trusted_image_certificates check."""

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
                "prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates import (
                compute_instance_trusted_image_certificates,
            )

            check = compute_instance_trusted_image_certificates()
            result = check.execute()

            assert len(result) == 0

    def test_instance_with_trusted_certificates(self):
        """Test instance with trusted image certificates (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="Trusted Instance",
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
                trusted_image_certificates=["cert-123", "cert-456"],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates import (
                compute_instance_trusted_image_certificates,
            )

            check = compute_instance_trusted_image_certificates()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended.startswith(
                "Instance Trusted Instance (instance-1) uses trusted image certificates:"
            )
            assert "cert-123" in result[0].status_extended
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "Trusted Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_without_trusted_certificates(self):
        """Test instance without trusted image certificates (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Untrusted Instance",
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
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates import (
                compute_instance_trusted_image_certificates,
            )

            check = compute_instance_trusted_image_certificates()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance Untrusted Instance (instance-2) does not use trusted image certificates (image signature validation not enforced)."
            )
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Untrusted Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_instances_mixed(self):
        """Test multiple instances with mixed certificate configuration."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-pass",
                name="Pass",
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
                trusted_image_certificates=["cert-789"],
            ),
            ComputeInstance(
                id="instance-fail",
                name="Fail",
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
                "prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_trusted_image_certificates.compute_instance_trusted_image_certificates import (
                compute_instance_trusted_image_certificates,
            )

            check = compute_instance_trusted_image_certificates()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
