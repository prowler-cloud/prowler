from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from openstack import exceptions as openstack_exceptions

from prowler.lib.logger import logger
from prowler.providers.openstack.lib.service.service import OpenStackService


class Image(OpenStackService):
    """Service wrapper using openstacksdk image (Glance) APIs."""

    def __init__(self, provider) -> None:
        super().__init__(__class__.__name__, provider)
        self.client = self.connection.image
        self.images: List[ImageResource] = []
        self._list_images()

    def _list_images(self) -> None:
        """List all images with their properties."""
        logger.info("Image - Listing images...")
        try:
            for img in self.client.images():
                # Skip images not owned by the current project (e.g. provider public images)
                owner = getattr(img, "owner_id", getattr(img, "owner", ""))
                if owner != self.project_id:
                    continue

                # Signature properties may be direct attributes or inside a properties dict
                properties = getattr(img, "properties", {}) or {}

                visibility = getattr(img, "visibility", "private")

                members = []
                if visibility == "shared":
                    members = self._list_image_members(getattr(img, "id", ""))

                self.images.append(
                    ImageResource(
                        id=getattr(img, "id", ""),
                        name=getattr(img, "name", ""),
                        status=getattr(img, "status", ""),
                        visibility=visibility,
                        protected=getattr(img, "is_protected", False),
                        owner=getattr(img, "owner_id", getattr(img, "owner", "")),
                        img_signature=self._resolve_property(
                            img, "img_signature", properties
                        ),
                        img_signature_hash_method=self._resolve_property(
                            img, "img_signature_hash_method", properties
                        ),
                        img_signature_key_type=self._resolve_property(
                            img, "img_signature_key_type", properties
                        ),
                        img_signature_certificate_uuid=self._resolve_property(
                            img, "img_signature_certificate_uuid", properties
                        ),
                        hw_mem_encryption=self._parse_bool(
                            self._resolve_property(img, "hw_mem_encryption", properties)
                        ),
                        os_secure_boot=self._resolve_property(
                            img,
                            "needs_secure_boot",
                            properties,
                            fallback_attr="os_secure_boot",
                        ),
                        members=members,
                        tags=getattr(img, "tags", []),
                        project_id=getattr(
                            img, "project_id", getattr(img, "owner", "")
                        ),
                        region=self.region,
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to list images: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error listing images: {error}"
            )

    @staticmethod
    def _resolve_property(
        img,
        attr_name: str,
        properties: dict,
        fallback_attr: str = None,
    ):
        """Get an image attribute, falling back to properties dict only when None.

        Uses ``is not None`` instead of ``or`` so that falsy values like
        ``False`` or ``""`` on the image object are preserved.

        Args:
            img: The SDK image object.
            attr_name: Primary SDK attribute name to check.
            properties: The image properties dict for final fallback.
            fallback_attr: Optional secondary attribute name to try before
                falling back to properties (e.g. when the SDK exposes a
                property under a different name like ``needs_secure_boot``
                vs ``os_secure_boot``).
        """
        value = getattr(img, attr_name, None)
        if value is not None:
            return value
        if fallback_attr is not None:
            value = getattr(img, fallback_attr, None)
            if value is not None:
                return value
        return properties.get(fallback_attr or attr_name)

    @staticmethod
    def _parse_bool(value) -> Optional[bool]:
        """Parse a boolean value that may be a string from the Glance API.

        Args:
            value: A bool, string ("True"/"False"), or None.

        Returns:
            True, False, or None.
        """
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() == "true"
        return None

    def _list_image_members(self, image_id: str) -> List[ImageMember]:
        """List members (shared projects) for a specific image.

        Args:
            image_id: The image UUID to list members for.

        Returns:
            List of ImageMember dataclasses.
        """
        members = []
        try:
            for member in self.client.members(image_id):
                members.append(
                    ImageMember(
                        member_id=getattr(
                            member, "member_id", getattr(member, "id", "")
                        ),
                        status=getattr(member, "status", "pending"),
                    )
                )
        except openstack_exceptions.SDKException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to list members for image {image_id}: {error}"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error listing members for image {image_id}: {error}"
            )
        return members


@dataclass
class ImageMember:
    """Represents a project that an image is shared with."""

    member_id: str
    status: str


@dataclass
class ImageResource:
    """Represents an OpenStack image."""

    id: str
    name: str
    status: str
    visibility: str
    protected: bool
    owner: str
    img_signature: Optional[str]
    img_signature_hash_method: Optional[str]
    img_signature_key_type: Optional[str]
    img_signature_certificate_uuid: Optional[str]
    hw_mem_encryption: Optional[bool]
    os_secure_boot: Optional[str]
    members: List[ImageMember] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    project_id: str = ""
    region: str = ""
