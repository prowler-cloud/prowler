"""Tests for image_not_publicly_visible check."""

from unittest import mock

from prowler.providers.openstack.services.image.image_service import ImageResource
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_image_not_publicly_visible:
    def test_no_images(self):
        """Test when no images exist."""
        image_client = mock.MagicMock()
        image_client.images = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible import (
                image_not_publicly_visible,
            )

            check = image_not_publicly_visible()
            result = check.execute()

            assert len(result) == 0

    def test_image_private(self):
        """Test PASS when image is private."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-1",
                name="private-image",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=[],
                tags=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible import (
                image_not_publicly_visible,
            )

            check = image_not_publicly_visible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image private-image (img-1) is not publicly visible (visibility=private)."
            )
            assert result[0].resource_id == "img-1"
            assert result[0].resource_name == "private-image"
            assert result[0].region == OPENSTACK_REGION

    def test_image_public(self):
        """Test FAIL when image is public."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-2",
                name="public-image",
                status="active",
                visibility="public",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=[],
                tags=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible import (
                image_not_publicly_visible,
            )

            check = image_not_publicly_visible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image public-image (img-2) is publicly visible to all tenants."
            )
            assert result[0].resource_id == "img-2"
            assert result[0].resource_name == "public-image"
            assert result[0].region == OPENSTACK_REGION

    def test_multiple_images_mixed(self):
        """Test mixed results with public, private, shared, and community images."""
        image_client = mock.MagicMock()
        base = dict(
            status="active",
            protected=False,
            owner=OPENSTACK_PROJECT_ID,
            img_signature=None,
            img_signature_hash_method=None,
            img_signature_key_type=None,
            img_signature_certificate_uuid=None,
            hw_mem_encryption=None,
            os_secure_boot=None,
            members=[],
            tags=[],
            project_id=OPENSTACK_PROJECT_ID,
            region=OPENSTACK_REGION,
        )
        image_client.images = [
            ImageResource(id="img-pub", name="public-img", visibility="public", **base),
            ImageResource(
                id="img-priv", name="private-img", visibility="private", **base
            ),
            ImageResource(
                id="img-shared", name="shared-img", visibility="shared", **base
            ),
            ImageResource(
                id="img-comm", name="community-img", visibility="community", **base
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_publicly_visible.image_not_publicly_visible import (
                image_not_publicly_visible,
            )

            check = image_not_publicly_visible()
            result = check.execute()

            assert len(result) == 4
            assert result[0].status == "FAIL"  # public
            assert result[1].status == "PASS"  # private
            assert result[2].status == "PASS"  # shared
            assert result[3].status == "PASS"  # community
