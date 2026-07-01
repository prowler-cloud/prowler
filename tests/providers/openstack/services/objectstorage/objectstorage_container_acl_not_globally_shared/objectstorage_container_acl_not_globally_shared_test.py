"""Tests for objectstorage_container_acl_not_globally_shared check."""

from unittest import mock

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_objectstorage_container_acl_not_globally_shared:
    """Test suite for objectstorage_container_acl_not_globally_shared check."""

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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 0

    def test_container_not_globally_shared(self):
        """Test container without global sharing (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-1",
                name="project-scoped",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=10,
                bytes_used=1024,
                read_ACL="project-123:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container project-scoped read ACL is not globally shared."
            )
            assert result[0].resource_id == "container-1"
            assert result[0].resource_name == "project-scoped"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_globally_shared(self):
        """Test container with global sharing (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-2",
                name="global-shared",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=5,
                bytes_used=512,
                read_ACL="*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container global-shared has globally shared read ACL (*:*) allowing all authenticated users from any project."
            )
            assert result[0].resource_id == "container-2"
            assert result[0].resource_name == "global-shared"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_globally_shared_bare_wildcard(self):
        """Test container with * (bare wildcard) read ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-3",
                name="bare-wildcard",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_container_star_colon_star_in_multi_entry_acl(self):
        """Test container with *:* in multi-entry read ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-4",
                name="multi-entry-global",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="project-123:user-456,*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiple_containers_mixed(self):
        """Test multiple containers with mixed ACLs."""
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
                read_ACL="*:*",
                write_ACL="",
                versioning_enabled=False,
                versions_location="",
                history_location="",
                sync_to="",
                sync_key="",
                metadata={},
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_acl_not_globally_shared.objectstorage_container_acl_not_globally_shared import (
                objectstorage_container_acl_not_globally_shared,
            )

            check = objectstorage_container_acl_not_globally_shared()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
