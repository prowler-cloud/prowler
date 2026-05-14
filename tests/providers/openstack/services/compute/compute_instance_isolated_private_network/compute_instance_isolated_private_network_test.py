"""Tests for compute_instance_isolated_private_network check."""

from unittest import mock

from prowler.providers.openstack.services.compute.compute_service import ComputeInstance
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_compute_instance_isolated_private_network:
    """Test suite for compute_instance_isolated_private_network check."""

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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 0

    def test_instance_private_only(self):
        """Test instance with private IP only (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-1",
                name="Isolated Instance",
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance Isolated Instance (instance-1) is properly isolated in private network with private IPs (10.0.0.5) and no public exposure."
            )
            assert result[0].resource_id == "instance-1"
            assert result[0].resource_name == "Isolated Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_mixed_public_private(self):
        """Test instance with both public and private IPs (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-2",
                name="Mixed Instance",
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
                public_v4="8.8.4.4",
                public_v6="",
                private_v4="10.0.0.10",
                private_v6="",
                networks={"public": ["8.8.4.4"], "private": ["10.0.0.10"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance Mixed Instance (instance-2) has mixed public and private network exposure (not properly isolated)."
            )
            assert result[0].resource_id == "instance-2"
            assert result[0].resource_name == "Mixed Instance"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_public_only(self):
        """Test instance with only public IP (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-3",
                name="Public Only",
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
                public_v4="1.1.1.1",
                public_v6="",
                private_v4="",
                private_v6="",
                networks={"public": ["1.1.1.1"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance Public Only (instance-3) has only public IP addresses (no private network isolation)."
            )
            assert result[0].resource_id == "instance-3"
            assert result[0].resource_name == "Public Only"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_no_ips(self):
        """Test instance with no IPs (FAIL)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-4",
                name="No IPs",
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Instance No IPs (instance-4) has no network configuration (no IPs assigned)."
            )
            assert result[0].resource_id == "instance-4"
            assert result[0].resource_name == "No IPs"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_private_ipv6_only(self):
        """Test instance with private IPv6 only (PASS)."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-5",
                name="IPv6 Private",
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Instance IPv6 Private (instance-5) is properly isolated in private network with private IPs (fd00::1) and no public exposure."
            )
            assert result[0].resource_id == "instance-5"
            assert result[0].resource_name == "IPv6 Private"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_instance_fallback_private_only_networks_dict(self):
        """Test fallback logic: instance with private IP populated by service from networks dict."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-fallback-1",
                name="Private Fallback",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="",  # Empty
                access_ipv6="",  # Empty
                public_v4="",  # Empty
                public_v6="",  # Empty
                private_v4="10.99.1.207",  # Populated by service fallback
                private_v6="",  # Empty
                networks={"test-private-net": ["10.99.1.207"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "10.99.1.207" in result[0].status_extended
            assert "properly isolated in private network" in result[0].status_extended
            assert result[0].resource_id == "instance-fallback-1"

    def test_instance_fallback_public_only_networks_dict(self):
        """Test fallback logic: instance with public IP populated by service from networks dict."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-fallback-2",
                name="Public Fallback",
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
                public_v4="8.8.8.8",  # Populated by service fallback
                public_v6="",  # Empty
                private_v4="",
                private_v6="",
                networks={"ext-net": ["8.8.8.8"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "only public IP addresses" in result[0].status_extended
                or "no private network isolation" in result[0].status_extended
            )
            assert result[0].resource_id == "instance-fallback-2"

    def test_instance_fallback_mixed_networks_dict(self):
        """Test fallback logic: instance with mixed IPs populated by service from networks dict."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-fallback-3",
                name="Mixed Fallback",
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
                public_v4="8.8.8.8",  # Populated by service fallback
                public_v6="",  # Empty
                private_v4="10.0.0.100",  # Populated by service fallback
                private_v6="",  # Empty
                networks={
                    "private-net": ["10.0.0.100"],
                    "ext-net": ["8.8.8.8"],
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "mixed public and private network exposure" in result[0].status_extended
            )
            assert result[0].resource_id == "instance-fallback-3"

    def test_instance_access_ipv4_private_treated_as_private(self):
        """Test that access_ipv4 set to a private IP is not treated as public exposure."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-access-priv",
                name="Access Private",
                status="ACTIVE",
                flavor_id="flavor-1",
                security_groups=["default"],
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                is_locked=False,
                locked_reason="",
                key_name="",
                user_id="",
                access_ipv4="10.0.0.50",
                access_ipv6="",
                public_v4="",
                public_v6="",
                private_v4="10.0.0.50",
                private_v6="",
                networks={"private-net": ["10.0.0.50"]},
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "properly isolated in private network" in result[0].status_extended
            assert result[0].resource_id == "instance-access-priv"

    def test_instance_network_ips_validated_as_public(self):
        """Test that IPs from networks dict are validated as truly public."""
        compute_client = mock.MagicMock()
        compute_client.instances = [
            ComputeInstance(
                id="instance-net-pub",
                name="Network Public",
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
                networks={
                    "my-net": ["10.0.0.5", "8.8.8.8"],
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
                "prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.openstack.services.compute.compute_instance_isolated_private_network.compute_instance_isolated_private_network import (
                compute_instance_isolated_private_network,
            )

            check = compute_instance_isolated_private_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "mixed public and private network exposure" in result[0].status_extended
            )
            assert result[0].resource_id == "instance-net-pub"
