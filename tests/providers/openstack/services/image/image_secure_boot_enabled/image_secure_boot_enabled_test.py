"""Tests for image_secure_boot_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.image.image_service import ImageResource
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_image_secure_boot_enabled:
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
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_image_secure_boot_required(self):
        """Test PASS when os_secure_boot is 'required'."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-1",
                name="secure-boot-image",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot="required",
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
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image secure-boot-image (img-1) has Secure Boot set to required."
            )
            assert result[0].resource_id == "img-1"
            assert result[0].resource_name == "secure-boot-image"
            assert result[0].region == OPENSTACK_REGION

    def test_image_secure_boot_not_set(self):
        """Test FAIL when os_secure_boot is None."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-2",
                name="no-secureboot-image",
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
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image no-secureboot-image (img-2) does not have Secure Boot set to required (os_secure_boot=None)."
            )

    def test_image_secure_boot_optional(self):
        """Test FAIL when os_secure_boot is 'optional'."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-3",
                name="optional-secureboot",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot="optional",
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
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_image_secure_boot_disabled(self):
        """Test FAIL when os_secure_boot is 'disabled'."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-4",
                name="disabled-secureboot",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot="disabled",
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
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiple_images_mixed(self):
        """Test mixed results with various secure boot settings."""
        image_client = mock.MagicMock()
        base = dict(
            status="active",
            visibility="private",
            protected=False,
            owner=OPENSTACK_PROJECT_ID,
            img_signature=None,
            img_signature_hash_method=None,
            img_signature_key_type=None,
            img_signature_certificate_uuid=None,
            hw_mem_encryption=None,
            members=[],
            tags=[],
            project_id=OPENSTACK_PROJECT_ID,
            region=OPENSTACK_REGION,
        )
        image_client.images = [
            ImageResource(
                id="img-req", name="required", os_secure_boot="required", **base
            ),
            ImageResource(
                id="img-opt", name="optional", os_secure_boot="optional", **base
            ),
            ImageResource(
                id="img-dis", name="disabled", os_secure_boot="disabled", **base
            ),
            ImageResource(id="img-none", name="none-set", os_secure_boot=None, **base),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_secure_boot_enabled.image_secure_boot_enabled import (
                image_secure_boot_enabled,
            )

            check = image_secure_boot_enabled()
            result = check.execute()

            assert len(result) == 4
            assert result[0].status == "PASS"  # required
            assert result[1].status == "FAIL"  # optional
            assert result[2].status == "FAIL"  # disabled
            assert result[3].status == "FAIL"  # None
