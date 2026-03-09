"""Tests for objectstorage_container_sync_not_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_objectstorage_container_sync_not_enabled:
    """Test suite for objectstorage_container_sync_not_enabled check."""

    def test_no_containers(self):
        """Test when no containers exist."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled import (
                objectstorage_container_sync_not_enabled,
            )

            check = objectstorage_container_sync_not_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_container_no_sync(self):
        """Test container without sync (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-1",
                name="no-sync",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled import (
                objectstorage_container_sync_not_enabled,
            )

            check = objectstorage_container_sync_not_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container no-sync does not have container sync enabled."
            )
            assert result[0].resource_id == "container-1"
            assert result[0].resource_name == "no-sync"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_with_sync(self):
        """Test container with sync enabled (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-2",
                name="synced-container",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=5,
                bytes_used=512,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="https://other-cluster/v1/AUTH_test/container-2",
                sync_key="shared-secret",
                metadata={},
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled import (
                objectstorage_container_sync_not_enabled,
            )

            check = objectstorage_container_sync_not_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container synced-container has container sync enabled (sync target: https://other-cluster/v1/AUTH_test/container-2)."
            )
            assert result[0].resource_id == "container-2"
            assert result[0].resource_name == "synced-container"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_multiple_containers_mixed(self):
        """Test multiple containers with mixed sync status."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-pass",
                name="Pass",
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
                metadata={},
            ),
            ObjectStorageContainer(
                id="container-fail",
                name="Fail",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="https://external/v1/AUTH_test/container",
                sync_key="key",
                metadata={},
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_sync_not_enabled.objectstorage_container_sync_not_enabled import (
                objectstorage_container_sync_not_enabled,
            )

            check = objectstorage_container_sync_not_enabled()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
