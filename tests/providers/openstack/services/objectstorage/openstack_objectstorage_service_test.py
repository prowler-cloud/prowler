"""Tests for OpenStack ObjectStorage service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorage,
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestObjectStorageService:
    """Test suite for ObjectStorage service."""

    def test_objectstorage_service_initialization(self):
        """Test ObjectStorage service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with patch.object(
            ObjectStorage, "_list_containers", return_value=[]
        ) as mock_list:
            service = ObjectStorage(provider)

            assert service.service_name == "ObjectStorage"
            assert service.provider == provider
            assert service.connection == provider.connection
            assert service.regional_connections == provider.regional_connections
            assert service.audited_regions == [OPENSTACK_REGION]
            assert service.region == OPENSTACK_REGION
            assert service.project_id == OPENSTACK_PROJECT_ID
            assert service.containers == []
            mock_list.assert_called_once()

    def test_objectstorage_list_containers_success(self):
        """Test listing containers successfully."""
        provider = set_mocked_openstack_provider()

        mock_container1 = MagicMock()
        mock_container1.name = "container-1"
        mock_container1.count = 10
        mock_container1.bytes = 1024
        mock_container1.read_ACL = ".r:*,.rlistings"
        mock_container1.write_ACL = "*:*"
        mock_container1.versions_location = "container-1_versions"
        mock_container1.history_location = ""
        mock_container1.sync_to = "https://other-cluster/v1/AUTH_test/container-1"
        mock_container1.sync_key = "shared-secret"
        mock_container1.metadata = {"environment": "production"}

        mock_container2 = MagicMock()
        mock_container2.name = "container-2"
        mock_container2.count = 0
        mock_container2.bytes = 0
        mock_container2.read_ACL = ""
        mock_container2.write_ACL = ""
        mock_container2.versions_location = ""
        mock_container2.history_location = ""
        mock_container2.sync_to = ""
        mock_container2.sync_key = ""
        mock_container2.metadata = {}

        provider.connection.object_store.containers.return_value = [
            mock_container1,
            mock_container2,
        ]

        # get_container_metadata returns the detailed mock for each container
        def mock_get_metadata(name):
            return {"container-1": mock_container1, "container-2": mock_container2}[
                name
            ]

        provider.connection.object_store.get_container_metadata.side_effect = (
            mock_get_metadata
        )

        service = ObjectStorage(provider)

        assert len(service.containers) == 2
        assert isinstance(service.containers[0], ObjectStorageContainer)
        assert service.containers[0].id == "container-1"
        assert service.containers[0].name == "container-1"
        assert service.containers[0].region == OPENSTACK_REGION
        assert service.containers[0].project_id == OPENSTACK_PROJECT_ID
        assert service.containers[0].object_count == 10
        assert service.containers[0].bytes_used == 1024
        assert service.containers[0].read_ACL == ".r:*,.rlistings"
        assert service.containers[0].write_ACL == "*:*"
        assert service.containers[0].versioning_enabled is True
        assert service.containers[0].versions_location == "container-1_versions"
        assert service.containers[0].history_location == ""
        assert (
            service.containers[0].sync_to
            == "https://other-cluster/v1/AUTH_test/container-1"
        )
        assert service.containers[0].sync_key == "shared-secret"
        assert service.containers[0].metadata == {"environment": "production"}

        assert service.containers[1].id == "container-2"
        assert service.containers[1].versioning_enabled is False
        assert service.containers[1].sync_to == ""
        assert service.containers[1].metadata == {}

    def test_objectstorage_list_containers_empty(self):
        """Test listing containers when none exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.object_store.containers.return_value = []

        service = ObjectStorage(provider)

        assert service.containers == []

    def test_objectstorage_list_containers_missing_attributes(self):
        """Test listing containers with missing attributes uses fallback to list data."""
        provider = set_mocked_openstack_provider()

        mock_container = MagicMock()
        mock_container.name = "container-1"
        del mock_container.count
        del mock_container.bytes
        del mock_container.read_ACL
        del mock_container.write_ACL
        del mock_container.versions_location
        del mock_container.history_location
        del mock_container.sync_to
        del mock_container.sync_key
        del mock_container.metadata

        provider.connection.object_store.containers.return_value = [mock_container]

        # HEAD also returns missing attributes (same mock)
        provider.connection.object_store.get_container_metadata.return_value = (
            mock_container
        )

        service = ObjectStorage(provider)

        assert len(service.containers) == 1
        assert service.containers[0].id == "container-1"
        assert service.containers[0].name == "container-1"
        assert service.containers[0].object_count == 0
        assert service.containers[0].bytes_used == 0
        assert service.containers[0].read_ACL == ""
        assert service.containers[0].write_ACL == ""
        assert service.containers[0].versioning_enabled is False
        assert service.containers[0].versions_location == ""
        assert service.containers[0].history_location == ""
        assert service.containers[0].sync_to == ""
        assert service.containers[0].sync_key == ""
        assert service.containers[0].metadata == {}

    def test_objectstorage_list_containers_head_failure_falls_back(self):
        """Test that HEAD failure falls back to list data gracefully."""
        provider = set_mocked_openstack_provider()

        mock_container = MagicMock()
        mock_container.name = "container-1"
        mock_container.count = 5
        mock_container.bytes = 256
        mock_container.read_ACL = None
        mock_container.write_ACL = None
        mock_container.versions_location = None
        mock_container.history_location = None
        mock_container.sync_to = None
        mock_container.sync_key = None
        mock_container.metadata = {}

        provider.connection.object_store.containers.return_value = [mock_container]
        provider.connection.object_store.get_container_metadata.side_effect = Exception(
            "HEAD failed"
        )

        service = ObjectStorage(provider)

        # Should still create the container using list data as fallback
        assert len(service.containers) == 1
        assert service.containers[0].name == "container-1"
        assert service.containers[0].object_count == 5
        assert service.containers[0].bytes_used == 256

    def test_objectstorage_list_containers_sdk_exception(self):
        """Test handling SDKException when listing containers."""
        provider = set_mocked_openstack_provider()
        provider.connection.object_store.containers.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        service = ObjectStorage(provider)

        assert service.containers == []

    def test_objectstorage_list_containers_generic_exception(self):
        """Test handling generic exception when listing containers."""
        provider = set_mocked_openstack_provider()
        provider.connection.object_store.containers.side_effect = Exception(
            "Unexpected error"
        )

        service = ObjectStorage(provider)

        assert service.containers == []

    def test_objectstorage_container_dataclass_attributes(self):
        """Test ObjectStorageContainer dataclass has all required attributes."""
        container = ObjectStorageContainer(
            id="container-1",
            name="container-1",
            region="RegionOne",
            project_id="project-1",
            object_count=10,
            bytes_used=1024,
            read_ACL=".r:*",
            write_ACL="*:*",
            versioning_enabled=True,
            versions_location="container-1_versions",
            history_location="",
            sync_to="https://other-cluster/v1/AUTH_test/container-1",
            sync_key="shared-secret",
            metadata={"environment": "production"},
        )

        assert container.id == "container-1"
        assert container.name == "container-1"
        assert container.region == "RegionOne"
        assert container.project_id == "project-1"
        assert container.object_count == 10
        assert container.bytes_used == 1024
        assert container.read_ACL == ".r:*"
        assert container.write_ACL == "*:*"
        assert container.versioning_enabled is True
        assert container.versions_location == "container-1_versions"
        assert container.history_location == ""
        assert container.sync_to == "https://other-cluster/v1/AUTH_test/container-1"
        assert container.sync_key == "shared-secret"
        assert container.metadata == {"environment": "production"}

    def test_objectstorage_service_inherits_from_base(self):
        """Test ObjectStorage service inherits from OpenStackService."""
        provider = set_mocked_openstack_provider()

        with patch.object(ObjectStorage, "_list_containers", return_value=[]):
            service = ObjectStorage(provider)

            assert hasattr(service, "service_name")
            assert hasattr(service, "provider")
            assert hasattr(service, "connection")
            assert hasattr(service, "regional_connections")
            assert hasattr(service, "audited_regions")
            assert hasattr(service, "session")
            assert hasattr(service, "region")
            assert hasattr(service, "project_id")
            assert hasattr(service, "identity")
            assert hasattr(service, "audit_config")
            assert hasattr(service, "fixer_config")

    def test_objectstorage_list_containers_multi_region(self):
        """Test listing containers across multiple regions."""
        provider = set_mocked_openstack_provider()

        # Create two mock connections for two regions
        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_container_uk = MagicMock()
        mock_container_uk.name = "container-uk"
        mock_container_uk.count = 5
        mock_container_uk.bytes = 512
        mock_container_uk.read_ACL = ""
        mock_container_uk.write_ACL = ""
        mock_container_uk.versions_location = ""
        mock_container_uk.history_location = ""
        mock_container_uk.sync_to = ""
        mock_container_uk.sync_key = ""
        mock_container_uk.metadata = {}

        mock_container_de = MagicMock()
        mock_container_de.name = "container-de"
        mock_container_de.count = 10
        mock_container_de.bytes = 1024
        mock_container_de.read_ACL = ".r:*"
        mock_container_de.write_ACL = ""
        mock_container_de.versions_location = ""
        mock_container_de.history_location = ""
        mock_container_de.sync_to = ""
        mock_container_de.sync_key = ""
        mock_container_de.metadata = {}

        mock_conn_uk1.object_store.containers.return_value = [mock_container_uk]
        mock_conn_uk1.object_store.get_container_metadata.return_value = (
            mock_container_uk
        )
        mock_conn_de1.object_store.containers.return_value = [mock_container_de]
        mock_conn_de1.object_store.get_container_metadata.return_value = (
            mock_container_de
        )

        service = ObjectStorage(provider)

        assert len(service.containers) == 2
        uk_container = next(c for c in service.containers if c.id == "container-uk")
        de_container = next(c for c in service.containers if c.id == "container-de")
        assert uk_container.region == "UK1"
        assert de_container.region == "DE1"

    def test_objectstorage_list_containers_multi_region_partial_failure(self):
        """Test that a failing region doesn't prevent other regions from being listed."""
        provider = set_mocked_openstack_provider()

        mock_conn_ok = MagicMock()
        mock_conn_fail = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_ok, "DE1": mock_conn_fail}

        mock_container = MagicMock()
        mock_container.name = "container-uk"
        mock_container.count = 5
        mock_container.bytes = 512
        mock_container.read_ACL = ""
        mock_container.write_ACL = ""
        mock_container.versions_location = ""
        mock_container.history_location = ""
        mock_container.sync_to = ""
        mock_container.sync_key = ""
        mock_container.metadata = {}

        mock_conn_ok.object_store.containers.return_value = [mock_container]
        mock_conn_ok.object_store.get_container_metadata.return_value = mock_container
        mock_conn_fail.object_store.containers.side_effect = (
            openstack_exceptions.SDKException("API error in DE1")
        )

        service = ObjectStorage(provider)

        assert len(service.containers) == 1
        assert service.containers[0].id == "container-uk"
        assert service.containers[0].region == "UK1"

    def test_objectstorage_list_containers_multi_region_one_empty(self):
        """Test multi-region where one region has containers and the other is empty."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_container = MagicMock()
        mock_container.name = "container-uk"
        mock_container.count = 5
        mock_container.bytes = 512
        mock_container.read_ACL = ""
        mock_container.write_ACL = ""
        mock_container.versions_location = ""
        mock_container.history_location = ""
        mock_container.sync_to = ""
        mock_container.sync_key = ""
        mock_container.metadata = {}

        mock_conn_uk1.object_store.containers.return_value = [mock_container]
        mock_conn_uk1.object_store.get_container_metadata.return_value = mock_container
        mock_conn_de1.object_store.containers.return_value = []

        service = ObjectStorage(provider)

        assert len(service.containers) == 1
        assert service.containers[0].id == "container-uk"
        assert service.containers[0].region == "UK1"

    def test_objectstorage_list_containers_history_location_versioning(self):
        """Test that history_location (X-History-Location) enables versioning."""
        provider = set_mocked_openstack_provider()

        mock_container = MagicMock()
        mock_container.name = "history-container"
        mock_container.count = 3
        mock_container.bytes = 256
        mock_container.read_ACL = ""
        mock_container.write_ACL = ""
        mock_container.versions_location = ""
        mock_container.history_location = "history-container_versions"
        mock_container.sync_to = ""
        mock_container.sync_key = ""
        mock_container.metadata = {}

        provider.connection.object_store.containers.return_value = [mock_container]
        provider.connection.object_store.get_container_metadata.return_value = (
            mock_container
        )

        service = ObjectStorage(provider)

        assert len(service.containers) == 1
        assert service.containers[0].versioning_enabled is True
        assert service.containers[0].versions_location == ""
        assert service.containers[0].history_location == "history-container_versions"
