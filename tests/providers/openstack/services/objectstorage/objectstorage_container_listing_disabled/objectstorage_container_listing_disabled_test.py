"""Tests for objectstorage_container_listing_disabled check."""

from unittest import mock

from prowler.providers.openstack.services.objectstorage.objectstorage_service import (
    ObjectStorageContainer,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_objectstorage_container_listing_disabled:
    """Test suite for objectstorage_container_listing_disabled check."""

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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_container_no_listing(self):
        """Test container without public listing (PASS)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-1",
                name="no-listing",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Container no-listing does not have public listing enabled."
            )
            assert result[0].resource_id == "container-1"
            assert result[0].resource_name == "no-listing"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_with_listing(self):
        """Test container with public listing (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-2",
                name="public-listing",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=5,
                bytes_used=512,
                read_ACL=".r:*,.rlistings",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container public-listing has public listing enabled (.rlistings) allowing anonymous object enumeration."
            )
            assert result[0].resource_id == "container-2"
            assert result[0].resource_name == "public-listing"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_listing_via_global_acl_star_colon_star(self):
        """Test container with *:* read ACL enabling listing (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-3",
                name="global-acl-listing",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Container global-acl-listing has listing enabled via global read ACL (*:*) allowing all authenticated users to list objects."
            )
            assert result[0].resource_id == "container-3"
            assert result[0].resource_name == "global-acl-listing"
            assert result[0].region == OPENSTACK_REGION
            assert result[0].project_id == OPENSTACK_PROJECT_ID

    def test_container_listing_via_bare_wildcard(self):
        """Test container with * read ACL enabling listing (FAIL)."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-4",
                name="bare-wildcard-listing",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_container_rlistings_takes_priority_over_global(self):
        """Test that .rlistings is reported when both .rlistings and *:* are present."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-5",
                name="both-patterns",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL=".rlistings,*:*",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert ".rlistings" in result[0].status_extended

    def test_multiple_containers_mixed(self):
        """Test multiple containers with mixed listing status."""
        objectstorage_client = mock.MagicMock()
        objectstorage_client.containers = [
            ObjectStorageContainer(
                id="container-pass",
                name="Pass",
                region=OPENSTACK_REGION,
                project_id=OPENSTACK_PROJECT_ID,
                object_count=0,
                bytes_used=0,
                read_ACL=".r:*",
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
                read_ACL=".r:*,.rlistings",
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
                "prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled.objectstorage_client",
                new=objectstorage_client,
            ),
        ):
            from prowler.providers.openstack.services.objectstorage.objectstorage_container_listing_disabled.objectstorage_container_listing_disabled import (
                objectstorage_container_listing_disabled,
            )

            check = objectstorage_container_listing_disabled()
            result = check.execute()

            assert len(result) == 2
            assert len([r for r in result if r.status == "PASS"]) == 1
            assert len([r for r in result if r.status == "FAIL"]) == 1
