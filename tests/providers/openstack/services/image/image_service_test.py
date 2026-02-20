"""Tests for OpenStack Image service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.image.image_service import (
    Image,
    ImageMember,
    ImageResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestImageService:
    """Test suite for Image service."""

    def test_image_service_initialization(self):
        """Test Image service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with patch.object(Image, "_list_images", return_value=[]):
            image_service = Image(provider)

            assert image_service.service_name == "Image"
            assert image_service.provider == provider
            assert image_service.connection == provider.connection
            assert image_service.region == OPENSTACK_REGION
            assert image_service.project_id == OPENSTACK_PROJECT_ID
            assert image_service.client == provider.connection.image
            assert image_service.images == []

    def test_image_list_images_success(self):
        """Test listing images successfully."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-1"
        mock_img.name = "ubuntu-22.04"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = True
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = ["production"]
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert isinstance(image_service.images[0], ImageResource)
        assert image_service.images[0].id == "img-1"
        assert image_service.images[0].name == "ubuntu-22.04"
        assert image_service.images[0].status == "active"
        assert image_service.images[0].visibility == "private"
        assert image_service.images[0].protected is True
        assert image_service.images[0].tags == ["production"]
        assert image_service.images[0].members == []

    def test_image_list_images_with_signature(self):
        """Test listing images with signature properties."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-signed"
        mock_img.name = "signed-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = "abc123sig"
        mock_img.img_signature_hash_method = "SHA-256"
        mock_img.img_signature_key_type = "RSA-PSS"
        mock_img.img_signature_certificate_uuid = "cert-uuid-123"
        mock_img.hw_mem_encryption = True
        mock_img.needs_secure_boot = "required"
        mock_img.os_secure_boot = "required"
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        img = image_service.images[0]
        assert img.img_signature == "abc123sig"
        assert img.img_signature_hash_method == "SHA-256"
        assert img.img_signature_key_type == "RSA-PSS"
        assert img.img_signature_certificate_uuid == "cert-uuid-123"
        assert img.hw_mem_encryption is True
        assert img.os_secure_boot == "required"

    def test_image_list_images_shared_with_members(self):
        """Test listing shared images fetches members."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-shared"
        mock_img.name = "shared-image"
        mock_img.status = "active"
        mock_img.visibility = "shared"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        mock_member = MagicMock()
        mock_member.member_id = "project-2"
        mock_member.id = "project-2"
        mock_member.status = "accepted"

        provider.connection.image.images.return_value = [mock_img]
        provider.connection.image.members.return_value = [mock_member]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert len(image_service.images[0].members) == 1
        assert isinstance(image_service.images[0].members[0], ImageMember)
        assert image_service.images[0].members[0].member_id == "project-2"
        assert image_service.images[0].members[0].status == "accepted"
        provider.connection.image.members.assert_called_once_with("img-shared")

    def test_image_list_images_private_no_member_fetch(self):
        """Test that private images do not trigger member listing."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-private"
        mock_img.name = "private-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert image_service.images[0].members == []
        provider.connection.image.members.assert_not_called()

    def test_image_list_images_empty(self):
        """Test listing images when none exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.image.images.return_value = []

        image_service = Image(provider)

        assert image_service.images == []

    def test_image_list_images_sdk_exception(self):
        """Test handling SDKException when listing images."""
        provider = set_mocked_openstack_provider()
        provider.connection.image.images.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        image_service = Image(provider)

        assert image_service.images == []

    def test_image_list_images_generic_exception(self):
        """Test handling generic Exception when listing images."""
        provider = set_mocked_openstack_provider()
        provider.connection.image.images.side_effect = Exception("Unexpected error")

        image_service = Image(provider)

        assert image_service.images == []

    def test_image_list_image_members_sdk_exception(self):
        """Test handling SDKException when listing image members."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-shared-err"
        mock_img.name = "shared-error-image"
        mock_img.status = "active"
        mock_img.visibility = "shared"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        provider.connection.image.images.return_value = [mock_img]
        provider.connection.image.members.side_effect = (
            openstack_exceptions.SDKException("Members API error")
        )

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert image_service.images[0].members == []

    def test_image_hw_mem_encryption_false_not_overridden_by_properties(self):
        """Test that hw_mem_encryption=False is preserved, not overridden by properties dict."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-enc-false"
        mock_img.name = "encryption-false-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = False
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {"hw_mem_encryption": "true"}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert image_service.images[0].hw_mem_encryption is False

    def test_image_os_secure_boot_disabled_not_overridden_by_properties(self):
        """Test that os_secure_boot='disabled' is preserved, not overridden by properties dict."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-boot-disabled"
        mock_img.name = "boot-disabled-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = "disabled"
        mock_img.os_secure_boot = "disabled"
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {"os_secure_boot": "required"}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert image_service.images[0].os_secure_boot == "disabled"

    def test_image_signature_empty_string_not_overridden_by_properties(self):
        """Test that empty string signature attrs are preserved, not overridden by properties."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-sig-empty"
        mock_img.name = "sig-empty-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = ""
        mock_img.img_signature_hash_method = ""
        mock_img.img_signature_key_type = ""
        mock_img.img_signature_certificate_uuid = ""
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {
            "img_signature": "should-not-override",
            "img_signature_hash_method": "should-not-override",
            "img_signature_key_type": "should-not-override",
            "img_signature_certificate_uuid": "should-not-override",
        }

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        img = image_service.images[0]
        assert img.img_signature == ""
        assert img.img_signature_hash_method == ""
        assert img.img_signature_key_type == ""
        assert img.img_signature_certificate_uuid == ""

    def test_image_properties_fallback_when_attrs_are_none(self):
        """Test that properties dict is used as fallback when image attrs are None."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-fallback"
        mock_img.name = "fallback-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = None
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {
            "img_signature": "prop-sig",
            "img_signature_hash_method": "SHA-256",
            "img_signature_key_type": "RSA-PSS",
            "img_signature_certificate_uuid": "cert-from-props",
            "hw_mem_encryption": "true",
            "os_secure_boot": "required",
        }

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        img = image_service.images[0]
        assert img.img_signature == "prop-sig"
        assert img.img_signature_hash_method == "SHA-256"
        assert img.img_signature_key_type == "RSA-PSS"
        assert img.img_signature_certificate_uuid == "cert-from-props"
        assert img.hw_mem_encryption is True
        assert img.os_secure_boot == "required"

    def test_image_needs_secure_boot_sdk_attr_resolved(self):
        """Test that needs_secure_boot (SDK attr) is used when os_secure_boot is absent."""
        provider = set_mocked_openstack_provider()

        mock_img = MagicMock()
        mock_img.id = "img-sdk-boot"
        mock_img.name = "sdk-boot-image"
        mock_img.status = "active"
        mock_img.visibility = "private"
        mock_img.is_protected = False
        mock_img.owner_id = OPENSTACK_PROJECT_ID
        mock_img.owner = OPENSTACK_PROJECT_ID
        mock_img.img_signature = None
        mock_img.img_signature_hash_method = None
        mock_img.img_signature_key_type = None
        mock_img.img_signature_certificate_uuid = None
        mock_img.hw_mem_encryption = None
        mock_img.needs_secure_boot = "required"
        mock_img.os_secure_boot = None
        mock_img.tags = []
        mock_img.project_id = OPENSTACK_PROJECT_ID
        mock_img.properties = {}

        provider.connection.image.images.return_value = [mock_img]

        image_service = Image(provider)

        assert len(image_service.images) == 1
        assert image_service.images[0].os_secure_boot == "required"
