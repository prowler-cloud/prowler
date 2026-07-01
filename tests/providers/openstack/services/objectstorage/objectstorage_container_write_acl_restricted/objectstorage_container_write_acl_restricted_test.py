"""Tests for objectstorage_container_write_acl_restricted check."""

from unittest import mock

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_objectstorage_container_write_acl_restricted:
    """Test suite for objectstorage_container_write_acl_restricted check."""

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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 0

    def test_container_restricted_write(self):
        """Test container with restricted write ACL (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-1",
                name="restricted-write",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=10,
                bytes_used=1024,
                read_ACL="",
                write_ACL="project-123:user-456",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container restricted-write has restricted write ACL."
            )
            assert result[0].resource_id == "container-1"
            assert result[0].resource_name == "restricted-write"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_unrestricted_write_star_colon_star(self):
        """Test container with *:* write ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-2",
                name="unrestricted-write",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=5,
                bytes_used=512,
                read_ACL="",
                write_ACL="*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container unrestricted-write has unrestricted write ACL allowing all authenticated users to write."
            )
            assert result[0].resource_id == "container-2"
            assert result[0].resource_name == "unrestricted-write"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_unrestricted_write_star_only(self):
        """Test container with * write ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-3",
                name="star-write",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_container_star_in_multi_entry_acl(self):
        """Test container with * in multi-entry write ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-4",
                name="star-multi-entry",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="*,project-123:user-456",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container star-multi-entry has unrestricted write ACL allowing all authenticated users to write."
            )

    def test_container_star_colon_star_in_multi_entry_acl(self):
        """Test container with *:* in multi-entry write ACL (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-5",
                name="star-colon-multi",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL="",
                write_ACL="project-123:user-456,*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiple_containers_mixed(self):
        """Test multiple containers with mixed write ACLs."""
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
                write_ACL="*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_write_acl_restricted.objectstorage_container_write_acl_restricted import (
                objectstorage_container_write_acl_restricted,
            )

            check = objectstorage_container_write_acl_restricted()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
