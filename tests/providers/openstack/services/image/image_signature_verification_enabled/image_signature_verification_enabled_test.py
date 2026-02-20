"""Tests for image_signature_verification_enabled check."""

from unittest import mock

from prowler.providers.openstack.services.image.image_service import ImageResource
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_image_signature_verification_enabled:
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
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_image_fully_signed(self):
        """Test PASS when all four signature properties are set."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-1",
                name="signed-image",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature="abc123sig",
                img_signature_hash_method="SHA-256",
                img_signature_key_type="RSA-PSS",
                img_signature_certificate_uuid="cert-uuid-123",
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
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image signed-image (img-1) has all signature verification properties configured."
            )
            assert result[0].resource_id == "img-1"
            assert result[0].resource_name == "signed-image"
            assert result[0].region == OPENSTACK_REGION

    def test_image_no_signatures(self):
        """Test FAIL when no signature properties are set."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-2",
                name="unsigned-image",
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
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image unsigned-image (img-2) does not have all signature verification properties configured."
            )

    def test_image_partial_signatures(self):
        """Test FAIL when only some signature properties are set."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-3",
                name="partial-sig-image",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature="abc123sig",
                img_signature_hash_method="SHA-256",
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
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_image_empty_string_signatures(self):
        """Test FAIL when signature properties are empty strings."""
        image_client = mock.MagicMock()
        image_client.images = [
            ImageResource(
                id="img-4",
                name="empty-sig-image",
                status="active",
                visibility="private",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature="",
                img_signature_hash_method="",
                img_signature_key_type="",
                img_signature_certificate_uuid="",
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
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiple_images_mixed(self):
        """Test mixed results with signed and unsigned images."""
        image_client = mock.MagicMock()
        base = dict(
            status="active",
            visibility="private",
            protected=False,
            owner=OPENSTACK_PROJECT_ID,
            hw_mem_encryption=None,
            os_secure_boot=None,
            members=[],
            tags=[],
            project_id=OPENSTACK_PROJECT_ID,
            region=OPENSTACK_REGION,
        )
        image_client.images = [
            ImageResource(
                id="img-signed",
                name="signed",
                img_signature="sig",
                img_signature_hash_method="SHA-256",
                img_signature_key_type="RSA-PSS",
                img_signature_certificate_uuid="cert-uuid",
                **base,
            ),
            ImageResource(
                id="img-unsigned",
                name="unsigned",
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                **base,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_signature_verification_enabled.image_signature_verification_enabled import (
                image_signature_verification_enabled,
            )

            check = image_signature_verification_enabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
