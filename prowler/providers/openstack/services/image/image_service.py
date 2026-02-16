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
                        img_signature=getattr(img, "img_signature", None)
                        or properties.get("img_signature"),
                        img_signature_hash_method=getattr(
                            img, "img_signature_hash_method", None
                        )
                        or properties.get("img_signature_hash_method"),
                        img_signature_key_type=getattr(
                            img, "img_signature_key_type", None
                        )
                        or properties.get("img_signature_key_type"),
                        img_signature_certificate_uuid=getattr(
                            img, "img_signature_certificate_uuid", None
                        )
                        or properties.get("img_signature_certificate_uuid"),
                        hw_mem_encryption=getattr(img, "hw_mem_encryption", None)
                        or properties.get("hw_mem_encryption"),
                        os_secure_boot=getattr(img, "os_secure_boot", None)
                        or properties.get("os_secure_boot"),
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
