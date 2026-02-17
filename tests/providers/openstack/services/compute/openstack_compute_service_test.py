"""Tests for OpenStack Compute service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.compute.compute_service import (
    Compute,
    ComputeInstance,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestComputeService:
    """Test suite for Compute service."""

    def test_compute_service_initialization(self):
        """Test Compute service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with patch.object(Compute, "_list_instances", return_value=[]) as mock_list:
            compute = Compute(provider)

            assert compute.service_name == "Compute"
            assert compute.provider == provider
            assert compute.connection == provider.connection
            assert compute.region == OPENSTACK_REGION
            assert compute.project_id == OPENSTACK_PROJECT_ID
            assert compute.client == provider.connection.compute
            assert compute.instances == []
            mock_list.assert_called_once()

    def test_compute_list_instances_success(self):
        """Test listing compute instances successfully."""
        provider = set_mocked_openstack_provider()

        mock_server1 = MagicMock()
        mock_server1.id = "instance-1"
        mock_server1.name = "Instance One"
        mock_server1.status = "ACTIVE"
        mock_server1.flavor = {"id": "flavor-1"}
        mock_server1.security_groups = [{"name": "default"}]
        mock_server1.is_locked = True
        mock_server1.locked_reason = "maintenance"
        mock_server1.key_name = "my-keypair"
        mock_server1.user_id = "user-123"
        mock_server1.access_ipv4 = "203.0.113.10"
        mock_server1.access_ipv6 = "2001:db8::1"
        mock_server1.public_v4 = "203.0.113.10"
        mock_server1.public_v6 = ""
        mock_server1.private_v4 = "10.0.0.5"
        mock_server1.private_v6 = ""
        mock_server1.addresses = {
            "private": [{"version": 4, "addr": "10.0.0.5"}],
            "public": [{"version": 4, "addr": "203.0.113.10"}],
        }
        mock_server1.has_config_drive = True
        mock_server1.metadata = {"environment": "production"}
        mock_server1.user_data = "#!/bin/bash\necho hello"
        mock_server1.trusted_image_certificates = ["cert-123"]

        mock_server2 = MagicMock()
        mock_server2.id = "instance-2"
        mock_server2.name = "Instance Two"
        mock_server2.status = "SHUTOFF"
        mock_server2.flavor = {"id": "flavor-2"}
        mock_server2.security_groups = [{"name": "web"}, {"name": "db"}]
        mock_server2.is_locked = False
        mock_server2.locked_reason = ""
        mock_server2.key_name = ""
        mock_server2.user_id = "user-456"
        mock_server2.access_ipv4 = ""
        mock_server2.access_ipv6 = ""
        mock_server2.public_v4 = ""
        mock_server2.public_v6 = ""
        mock_server2.private_v4 = "10.0.0.10"
        mock_server2.private_v6 = ""
        mock_server2.addresses = {"private": [{"version": 4, "addr": "10.0.0.10"}]}
        mock_server2.has_config_drive = False
        mock_server2.metadata = {}
        mock_server2.user_data = ""
        mock_server2.trusted_image_certificates = []

        provider.connection.compute.servers.return_value = [
            mock_server1,
            mock_server2,
        ]

        compute = Compute(provider)

        assert len(compute.instances) == 2
        assert isinstance(compute.instances[0], ComputeInstance)
        assert compute.instances[0].id == "instance-1"
        assert compute.instances[0].name == "Instance One"
        assert compute.instances[0].status == "ACTIVE"
        assert compute.instances[0].flavor_id == "flavor-1"
        assert compute.instances[0].security_groups == ["default"]
        assert compute.instances[0].region == OPENSTACK_REGION
        assert compute.instances[0].project_id == OPENSTACK_PROJECT_ID
        assert compute.instances[0].is_locked is True
        assert compute.instances[0].locked_reason == "maintenance"
        assert compute.instances[0].key_name == "my-keypair"
        assert compute.instances[0].user_id == "user-123"
        assert compute.instances[0].access_ipv4 == "203.0.113.10"
        assert compute.instances[0].access_ipv6 == "2001:db8::1"
        assert compute.instances[0].public_v4 == "203.0.113.10"
        assert compute.instances[0].private_v4 == "10.0.0.5"
        assert compute.instances[0].networks == {
            "private": ["10.0.0.5"],
            "public": ["203.0.113.10"],
        }
        assert compute.instances[0].has_config_drive is True
        assert compute.instances[0].metadata == {"environment": "production"}
        assert compute.instances[0].user_data == "#!/bin/bash\necho hello"
        assert compute.instances[0].trusted_image_certificates == ["cert-123"]

        assert compute.instances[1].security_groups == ["web", "db"]
        assert compute.instances[1].is_locked is False
        assert compute.instances[1].key_name == ""
        assert compute.instances[1].trusted_image_certificates == []

    def test_compute_list_instances_empty(self):
        """Test listing instances when none exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.compute.servers.return_value = []

        compute = Compute(provider)

        assert compute.instances == []

    def test_compute_list_instances_missing_attributes(self):
        """Test listing instances with missing attributes."""
        provider = set_mocked_openstack_provider()

        mock_server = MagicMock()
        mock_server.id = "instance-1"
        del mock_server.name
        del mock_server.status
        del mock_server.flavor
        del mock_server.security_groups
        del mock_server.is_locked
        del mock_server.locked_reason
        del mock_server.key_name
        del mock_server.user_id
        del mock_server.access_ipv4
        del mock_server.access_ipv6
        del mock_server.public_v4
        del mock_server.public_v6
        del mock_server.private_v4
        del mock_server.private_v6
        del mock_server.addresses
        del mock_server.has_config_drive
        del mock_server.metadata
        del mock_server.user_data
        del mock_server.trusted_image_certificates

        provider.connection.compute.servers.return_value = [mock_server]

        compute = Compute(provider)

        assert len(compute.instances) == 1
        assert compute.instances[0].id == "instance-1"
        assert compute.instances[0].name == ""
        assert compute.instances[0].status == ""
        assert compute.instances[0].flavor_id == ""
        assert compute.instances[0].security_groups == []
        assert compute.instances[0].is_locked is False
        assert compute.instances[0].locked_reason == ""
        assert compute.instances[0].key_name == ""
        assert compute.instances[0].user_id == ""
        assert compute.instances[0].access_ipv4 == ""
        assert compute.instances[0].access_ipv6 == ""
        assert compute.instances[0].public_v4 == ""
        assert compute.instances[0].public_v6 == ""
        assert compute.instances[0].private_v4 == ""
        assert compute.instances[0].private_v6 == ""
        assert compute.instances[0].networks == {}
        assert compute.instances[0].has_config_drive is False
        assert compute.instances[0].metadata == {}
        assert compute.instances[0].user_data == ""
        assert compute.instances[0].trusted_image_certificates == []

    def test_compute_list_instances_sdk_exception(self):
        """Test handling SDKException when listing instances."""
        provider = set_mocked_openstack_provider()
        provider.connection.compute.servers.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        compute = Compute(provider)

        assert compute.instances == []

    def test_compute_list_instances_generic_exception(self):
        """Test handling generic exception when listing instances."""
        provider = set_mocked_openstack_provider()
        provider.connection.compute.servers.side_effect = Exception("Unexpected error")

        compute = Compute(provider)

        assert compute.instances == []

    def test_compute_list_instances_iterator_exception(self):
        """Test listing instances when iterator fails mid-stream."""
        provider = set_mocked_openstack_provider()

        def failing_iterator():
            mock_server = MagicMock()
            mock_server.id = "instance-1"
            mock_server.name = "Instance One"
            mock_server.status = "ACTIVE"
            mock_server.flavor = {"id": "flavor-1"}
            mock_server.security_groups = [{"name": "default"}]
            mock_server.is_locked = False
            mock_server.locked_reason = ""
            mock_server.key_name = ""
            mock_server.user_id = ""
            mock_server.access_ipv4 = ""
            mock_server.access_ipv6 = ""
            mock_server.public_v4 = ""
            mock_server.public_v6 = ""
            mock_server.private_v4 = ""
            mock_server.private_v6 = ""
            mock_server.addresses = {}
            mock_server.has_config_drive = False
            mock_server.metadata = {}
            mock_server.user_data = ""
            mock_server.trusted_image_certificates = []
            yield mock_server
            raise Exception("Iterator failed")

        provider.connection.compute.servers.return_value = failing_iterator()

        compute = Compute(provider)

        assert len(compute.instances) == 1
        assert compute.instances[0].id == "instance-1"
        assert compute.instances[0].name == "Instance One"

    def test_compute_instance_dataclass_attributes(self):
        """Test ComputeInstance dataclass has all required attributes."""
        instance = ComputeInstance(
            id="instance-1",
            name="Instance One",
            status="ACTIVE",
            flavor_id="flavor-1",
            security_groups=["default"],
            region="RegionOne",
            project_id="project-1",
            is_locked=True,
            locked_reason="maintenance",
            key_name="my-keypair",
            user_id="user-123",
            access_ipv4="203.0.113.10",
            access_ipv6="2001:db8::1",
            public_v4="203.0.113.10",
            public_v6="",
            private_v4="10.0.0.5",
            private_v6="",
            networks={
                "private": ["10.0.0.5"]
            },  # Note: This is the processed dict, not addresses
            has_config_drive=True,
            metadata={"environment": "production"},
            user_data="#!/bin/bash\necho hello",
            trusted_image_certificates=["cert-123"],
        )

        assert instance.id == "instance-1"
        assert instance.name == "Instance One"
        assert instance.status == "ACTIVE"
        assert instance.flavor_id == "flavor-1"
        assert instance.security_groups == ["default"]
        assert instance.region == "RegionOne"
        assert instance.project_id == "project-1"
        assert instance.is_locked is True
        assert instance.locked_reason == "maintenance"
        assert instance.key_name == "my-keypair"
        assert instance.user_id == "user-123"
        assert instance.access_ipv4 == "203.0.113.10"
        assert instance.access_ipv6 == "2001:db8::1"
        assert instance.public_v4 == "203.0.113.10"
        assert instance.public_v6 == ""
        assert instance.private_v4 == "10.0.0.5"
        assert instance.private_v6 == ""
        assert instance.networks == {"private": ["10.0.0.5"]}
        assert instance.has_config_drive is True
        assert instance.metadata == {"environment": "production"}
        assert instance.user_data == "#!/bin/bash\necho hello"
        assert instance.trusted_image_certificates == ["cert-123"]

    def test_compute_service_inherits_from_base(self):
        """Test Compute service inherits from OpenStackService."""
        provider = set_mocked_openstack_provider()

        with patch.object(Compute, "_list_instances", return_value=[]):
            compute = Compute(provider)

            assert hasattr(compute, "service_name")
            assert hasattr(compute, "provider")
            assert hasattr(compute, "connection")
            assert hasattr(compute, "session")
            assert hasattr(compute, "region")
            assert hasattr(compute, "project_id")
            assert hasattr(compute, "identity")
            assert hasattr(compute, "audit_config")
            assert hasattr(compute, "fixer_config")

    def test_compute_list_instances_with_none_addresses(self):
        """Test listing instances when addresses attribute is None."""
        provider = set_mocked_openstack_provider()

        mock_server = MagicMock()
        mock_server.id = "instance-1"
        mock_server.name = "Instance With None Addresses"
        mock_server.status = "ACTIVE"
        mock_server.flavor = {"id": "flavor-1"}
        mock_server.security_groups = [{"name": "default"}]
        mock_server.is_locked = False
        mock_server.locked_reason = ""
        mock_server.key_name = "test-key"
        mock_server.user_id = "user-123"
        mock_server.access_ipv4 = ""
        mock_server.access_ipv6 = ""
        mock_server.public_v4 = ""
        mock_server.public_v6 = ""
        mock_server.private_v4 = ""
        mock_server.private_v6 = ""
        mock_server.addresses = None  # This is the key test case
        mock_server.has_config_drive = False
        mock_server.metadata = {}
        mock_server.user_data = ""
        mock_server.trusted_image_certificates = []

        provider.connection.compute.servers.return_value = [mock_server]

        compute = Compute(provider)

        assert len(compute.instances) == 1
        assert compute.instances[0].id == "instance-1"
        assert compute.instances[0].networks == {}  # Should default to empty dict
