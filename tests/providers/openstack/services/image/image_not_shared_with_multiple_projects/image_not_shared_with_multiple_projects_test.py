"""Tests for image_not_shared_with_multiple_projects check."""

from unittest import mock

from prowler.providers.openstack.services.image.image_service import (
    ImageMember,
    ImageResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_image_not_shared_with_multiple_projects:
    def test_no_images(self):
        """Test when no images exist."""
        image_client = mock.MagicMock()
        image_client.images = []
        image_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 0

    def test_image_not_shared(self):
        """Test PASS when image is not shared."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image private-image (img-1) is not shared (visibility=private)."
            )
            assert result[0].resource_id == "img-1"

    def test_image_shared_within_threshold(self):
        """Test PASS when shared image has accepted members within threshold."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
        members = [
            ImageMember(member_id=f"project-{i}", status="accepted") for i in range(3)
        ]
        image_client.images = [
            ImageResource(
                id="img-2",
                name="shared-image",
                status="active",
                visibility="shared",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=members,
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image shared-image (img-2) is shared with 3 accepted projects, within the threshold of 5."
            )

    def test_image_shared_at_threshold(self):
        """Test PASS when accepted members exactly equal threshold."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
        members = [
            ImageMember(member_id=f"project-{i}", status="accepted") for i in range(5)
        ]
        image_client.images = [
            ImageResource(
                id="img-3",
                name="threshold-image",
                status="active",
                visibility="shared",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=members,
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image threshold-image (img-3) is shared with 5 accepted projects, within the threshold of 5."
            )

    def test_image_shared_above_threshold(self):
        """Test FAIL when accepted members exceed threshold."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
        members = [
            ImageMember(member_id=f"project-{i}", status="accepted") for i in range(8)
        ]
        image_client.images = [
            ImageResource(
                id="img-4",
                name="overshared-image",
                status="active",
                visibility="shared",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=members,
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image overshared-image (img-4) is shared with 8 accepted projects, exceeding the threshold of 5."
            )

    def test_pending_members_not_counted(self):
        """Test that pending and rejected members are not counted."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
        members = [
            ImageMember(member_id="project-1", status="accepted"),
            ImageMember(member_id="project-2", status="pending"),
            ImageMember(member_id="project-3", status="rejected"),
            ImageMember(member_id="project-4", status="pending"),
            ImageMember(member_id="project-5", status="accepted"),
            ImageMember(member_id="project-6", status="pending"),
            ImageMember(member_id="project-7", status="pending"),
            ImageMember(member_id="project-8", status="pending"),
            ImageMember(member_id="project-9", status="pending"),
            ImageMember(member_id="project-10", status="pending"),
        ]
        image_client.images = [
            ImageResource(
                id="img-5",
                name="pending-members-image",
                status="active",
                visibility="shared",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=members,
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Image pending-members-image (img-5) is shared with 2 accepted projects, within the threshold of 5."
            )

    def test_custom_threshold_via_audit_config(self):
        """Test custom threshold from audit_config."""
        image_client = mock.MagicMock()
        image_client.audit_config = {"image_sharing_threshold": 2}
        members = [
            ImageMember(member_id=f"project-{i}", status="accepted") for i in range(3)
        ]
        image_client.images = [
            ImageResource(
                id="img-6",
                name="custom-threshold-image",
                status="active",
                visibility="shared",
                protected=False,
                owner=OPENSTACK_PROJECT_ID,
                img_signature=None,
                img_signature_hash_method=None,
                img_signature_key_type=None,
                img_signature_certificate_uuid=None,
                hw_mem_encryption=None,
                os_secure_boot=None,
                members=members,
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
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Image custom-threshold-image (img-6) is shared with 3 accepted projects, exceeding the threshold of 2."
            )

    def test_multiple_images_mixed(self):
        """Test mixed results with shared and non-shared images."""
        image_client = mock.MagicMock()
        image_client.audit_config = {}
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
            tags=[],
            project_id=OPENSTACK_PROJECT_ID,
            region=OPENSTACK_REGION,
        )
        image_client.images = [
            ImageResource(
                id="img-priv",
                name="private",
                visibility="private",
                members=[],
                **base,
            ),
            ImageResource(
                id="img-over",
                name="overshared",
                visibility="shared",
                members=[
                    ImageMember(member_id=f"p-{i}", status="accepted") for i in range(6)
                ],
                **base,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects.image_client",
                new=image_client,
            ),
        ):
            from prowler.providers.openstack.services.image.image_not_shared_with_multiple_projects.image_not_shared_with_multiple_projects import (
                image_not_shared_with_multiple_projects,
            )

            check = image_not_shared_with_multiple_projects()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"  # private
            assert result[1].status == "FAIL"  # overshared
