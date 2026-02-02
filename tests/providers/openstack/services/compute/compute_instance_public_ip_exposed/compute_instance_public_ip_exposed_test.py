"""Tests for compute_instance_public_ip_exposed check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_public_ip_exposed:
    """Test suite for compute_instance_public_ip_exposed check."""

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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 0

    def test_instance_without_public_ip(self):
        """Test instance without public IP (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="Private Instance",
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
                private_v4="10.0.0.5",
                private_v6="",
                networks={"private": ["10.0.0.5"]},  # Processed from addresses
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance Private Instance (instance-1) is not exposed to the internet (no public IP addresses or external network attachments detected)."
            )
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "Private Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_with_public_ipv4(self):
        """Test instance with public IPv4 (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Public Instance",
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
                public_v4="203.0.113.10",
                public_v6="",
                private_v4="10.0.0.10",
                private_v6="",
                networks={"public": ["203.0.113.10"], "private": ["10.0.0.10"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance Public Instance (instance-2) is exposed to the internet with public IP addresses:"
            )
            assert "203.0.113.10" in result[0].status_extended
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Public Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_with_access_ipv4(self):
        """Test instance with access IPv4 (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-3",
                name="Access IP Instance",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="198.51.100.5",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="10.0.0.15",
                private_v6="",
                networks={"private": ["10.0.0.15"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance Access IP Instance (instance-3) is exposed to the internet with public IP addresses:"
            )
            assert "198.51.100.5" in result[0].status_extended
            assert result[0].resource_id == "instance-3"
            assert result[0].resource_name == "Access IP Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_with_ipv6(self):
        """Test instance with public IPv6 (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-4",
                name="IPv6 Instance",
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
                access_ipv6="2001:db8::1",
                public_v4="",
                public_v6="",
                private_v4="",
                private_v6="fd00::1",
                networks={"private": ["fd00::1"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended.startswith(
                "Instance IPv6 Instance (instance-4) is exposed to the internet with public IP addresses:"
            )
            assert "2001:db8::1" in result[0].status_extended
            assert result[0].resource_id == "instance-4"
            assert result[0].resource_name == "IPv6 Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_instances_mixed(self):
        """Test multiple instances with mixed public IP configuration."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-pass",
                name="Private",
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
                private_v4="10.0.0.20",
                private_v6="",
                networks={"private": ["10.0.0.20"]},
                has_config_drive=False,
                metadata={},
                user_data="",
                trusted_image_certificates=[],
            ),
            ComputeInstance(
                id="instance-fail",
                name="Public",
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
                public_v4="203.0.113.20",
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1

    def test_instance_on_external_network(self):
        """Test instance directly attached to external network (OVH-style)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-extnet",
                name="ExtNet Instance",
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
                public_v4="",  # SDK might not populate this
                public_v6="",
                private_v4="",
                private_v6="",
                networks={
                    "Ext-Net": ["57.128.163.151", "2001:41d0:801:1000::164b"]
                },  # OVH external network
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "57.128.163.151" in result[0].status_extended
            assert "Ext-Net" in result[0].status_extended
            assert result[0].resource_id
            assert result[0].resource_name
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_mixed_networks_private_and_external(self):
        """Test instance with both private and external network attachments."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-mixed",
                name="Mixed Networks",
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
                private_v4="10.0.0.5",
                private_v6="",
                networks={
                    "private-net": ["10.0.0.5"],
                    "public-network": ["8.8.8.8"],  # Real public IP (Google DNS)
                },
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
                "prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_public_ip_exposed.compute_instance_public_ip_exposed import (
                compute_instance_public_ip_exposed,
            )

            check = compute_instance_public_ip_exposed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "8.8.8.8" in result[0].status_extended
            assert "public-network" in result[0].status_extended
            assert result[0].resource_id
            assert result[0].resource_name
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID
