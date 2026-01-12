from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestComputeInstanceDiskAutoDeleteDisabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_disk_auto_delete_disabled(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone=f"{GCP_US_CENTER1_LOCATION}-a",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[
                        {"email": "123-compute@developer.gserviceaccount.com"}
                    ],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[
                        Disk(
                            name="boot-disk",
                            auto_delete=False,
                            boot=True,
                            encryption=False,
                        ),
                        Disk(
                            name="data-disk",
                            auto_delete=False,
                            boot=False,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has auto-delete disabled for all attached disks."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_disk_auto_delete_enabled_single_disk(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone=f"{GCP_US_CENTER1_LOCATION}-a",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[
                        {"email": "123-compute@developer.gserviceaccount.com"}
                    ],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[
                        Disk(
                            name="boot-disk",
                            auto_delete=True,
                            boot=True,
                            encryption=False,
                        ),
                        Disk(
                            name="data-disk",
                            auto_delete=False,
                            boot=False,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has auto-delete enabled for the following disks: boot-disk."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_disk_auto_delete_enabled_multiple_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone=f"{GCP_US_CENTER1_LOCATION}-a",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[
                        {"email": "123-compute@developer.gserviceaccount.com"}
                    ],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[
                        Disk(
                            name="boot-disk",
                            auto_delete=True,
                            boot=True,
                            encryption=False,
                        ),
                        Disk(
                            name="data-disk",
                            auto_delete=True,
                            boot=False,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has auto-delete enabled for the following disks: boot-disk, data-disk."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_no_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone=f"{GCP_US_CENTER1_LOCATION}-a",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[
                        {"email": "123-compute@developer.gserviceaccount.com"}
                    ],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[],
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has auto-delete disabled for all attached disks."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_instances_mixed_results(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_disk_auto_delete_disabled.compute_instance_disk_auto_delete_disabled import (
                compute_instance_disk_auto_delete_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="compliant-instance",
                    id="1111111111",
                    zone=f"{GCP_US_CENTER1_LOCATION}-a",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[
                        Disk(
                            name="boot-disk",
                            auto_delete=False,
                            boot=True,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                ),
                Instance(
                    name="non-compliant-instance",
                    id="2222222222",
                    zone=f"{GCP_US_CENTER1_LOCATION}-b",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[
                        Disk(
                            name="auto-delete-disk",
                            auto_delete=True,
                            boot=True,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                ),
            ]

            check = compute_instance_disk_auto_delete_disabled()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "PASS"
            assert result[0].resource_name == "compliant-instance"

            assert result[1].status == "FAIL"
            assert result[1].resource_name == "non-compliant-instance"
            assert "auto-delete-disk" in result[1].status_extended
