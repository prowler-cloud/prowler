"""Tests for objectstorage_container_metadata_sensitive_data check."""

from unittest import mock

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_objectstorage_container_metadata_sensitive_data:
    """Test suite for objectstorage_container_metadata_sensitive_data check."""

    def test_no_containers(self):
        """Test when no containers exist."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = []
        objectstorage_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data import (
                objectstorage_container_metadata_sensitive_data,
            )

            check = objectstorage_container_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 0

    def test_container_no_metadata(self):
        """Test container with no metadata (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.audit_config = {}
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-1",
                name="no-metadata",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=10,
                bytes_used=1024,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={},
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data import (
                objectstorage_container_metadata_sensitive_data,
            )

            check = objectstorage_container_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container no-metadata has no metadata (no sensitive data exposure risk)."
            )
            assert result[0].resource_id == "container-1"
            assert result[0].resource_name == "no-metadata"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_safe_metadata(self):
        """Test container with safe metadata (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.audit_config = {}
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-2",
                name="safe-metadata",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=5,
                bytes_used=512,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={"environment": "production", "application": "web-app"},
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data import (
                objectstorage_container_metadata_sensitive_data,
            )

            check = objectstorage_container_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container safe-metadata metadata does not contain sensitive data."
            )

    def test_container_password_in_metadata(self):
        """Test container with password in metadata (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.audit_config = {}
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-3",
                name="password-metadata",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={"db_password": "supersecret123"},
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data import (
                objectstorage_container_metadata_sensitive_data,
            )

            check = objectstorage_container_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "contains potential secrets" in result[0].status_extended

    def test_multiple_containers_mixed(self):
        """Test multiple containers with mixed metadata."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.audit_config = {}
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-pass",
                name="Safe",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={"tier": "web"},
            ),
            ObjectStorageContainer(
                id="container-fail",
                name="Unsafe",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={"admin_password": "secret123"},
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_metadata_sensitive_data.objectstorage_container_metadata_sensitive_data import (
                objectstorage_container_metadata_sensitive_data,
            )

            check = objectstorage_container_metadata_sensitive_data()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
