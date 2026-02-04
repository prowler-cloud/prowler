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

        mock_server2 = MagicMock()
        mock_server2.id = "instance-2"
        mock_server2.name = "Instance Two"
        mock_server2.status = "SHUTOFF"
        mock_server2.flavor = {"id": "flavor-2"}
        mock_server2.security_groups = [{"name": "web"}, {"name": "db"}]

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

        assert compute.instances[1].security_groups == ["web", "db"]

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

        provider.connection.compute.servers.return_value = [mock_server]

        compute = Compute(provider)

        assert len(compute.instances) == 1
        assert compute.instances[0].id == "instance-1"
        assert compute.instances[0].name == ""
        assert compute.instances[0].status == ""
        assert compute.instances[0].flavor_id == ""
        assert compute.instances[0].security_groups == []

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
        )

        assert instance.id == "instance-1"
        assert instance.name == "Instance One"
        assert instance.status == "ACTIVE"
        assert instance.flavor_id == "flavor-1"
        assert instance.security_groups == ["default"]
        assert instance.region == "RegionOne"
        assert instance.project_id == "project-1"

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
