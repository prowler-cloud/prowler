"""Tests for image_protected_status_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.image.image_service import ImageResource
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_image_protected_status_enabled:
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
                "prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled import (
                image_protected_status_enabled,
            )

            check = image_protected_status_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_image_protected(self):
        """Test PASS when image is protected."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-1",
                name="protected-image",
                status="active",
                visibility="private",
                protected=True,
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
                "prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled import (
                image_protected_status_enabled,
            )

            check = image_protected_status_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image protected-image (img-1) has deletion protection enabled."
            )
            assert result[0].resource_id == "img-1"
            assert result[0].resource_name == "protected-image"
            assert result[0].region == OPENSTACK_REGION

    def test_image_not_protected(self):
        """Test FAIL when image is not protected."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-2",
                name="unprotected-image",
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
                "prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled import (
                image_protected_status_enabled,
            )

            check = image_protected_status_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image unprotected-image (img-2) does not have deletion protection enabled."
            )
            assert result[0].resource_id == "img-2"

    def test_multiple_images_mixed(self):
        """Test mixed results with protected and unprotected images."""
        image_client = mock.MagicMock()
        base = dict(
            status="active",
            visibility="private",
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
            ImageResource(id="img-p", name="protected", protected=True, **base),
            ImageResource(id="img-u", name="unprotected", protected=False, **base),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_protected_status_enabled.image_protected_status_enabled import (
                image_protected_status_enabled,
            )

            check = image_protected_status_enabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
