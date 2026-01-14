from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_approved_image:
    def test_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []
        compute_client.audit_config = {"approved_vm_images": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()
            assert len(result) == 0

    def test_instance_no_approved_list_configured(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-11-bullseye-v20231010",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {"approved_vm_images": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no approved image list configured" in result[0].status_extended
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-instance"

    def test_instance_approved_image_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/my-org/global/images/golden-image-v1",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/my-org/global/images/golden-.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "launched from an approved image" in result[0].status_extended
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-instance"

    def test_instance_unapproved_image_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/random-project/global/images/random-image",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/my-org/global/images/golden-.*",
                "projects/debian-cloud/.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not launched from an approved image" in result[0].status_extended
            assert (
                "random-project/global/images/random-image" in result[0].status_extended
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-instance"

    def test_instance_no_source_image_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image=None,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/my-org/global/images/golden-.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no source image information available" in result[0].status_extended
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-instance"

    def test_multiple_instances_mixed_results(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance_approved = Instance(
            name="approved-instance",
            id="111111111",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-11",
        )

        instance_unapproved = Instance(
            name="unapproved-instance",
            id="222222222",
            zone="us-central1-b",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/random/global/images/unapproved",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance_approved, instance_unapproved]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/debian-cloud/.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].resource_id == "111111111"
            assert result[1].status == "FAIL"
            assert result[1].resource_id == "222222222"

    def test_instance_case_insensitive_match(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/PROJECTS/debian-cloud/global/IMAGES/debian-11",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/debian-cloud/.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_default_approved_images_when_not_configured(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test-instance",
            id="1234567890",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/any-project/global/images/any-image",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no approved image list configured" in result[0].status_extended

    def test_gke_instance_manual_review(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="gke-cluster-default-pool-12345678-abcd",
            id="9876543210",
            zone="us-central1-a",
            region="us-central1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=True,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            source_image="https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-109-17800-147-54",
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]
        compute_client.audit_config = {
            "approved_vm_images": [
                "projects/my-org/global/images/golden-.*",
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_approved_image.compute_instance_approved_image import (
                compute_instance_approved_image,
            )

            check = compute_instance_approved_image()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "GKE-managed node" in result[0].status_extended
            assert "Google-managed images" in result[0].status_extended
            assert "cos-cloud" in result[0].status_extended
            assert result[0].resource_id == "9876543210"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "gke-cluster-default-pool-12345678-abcd"
