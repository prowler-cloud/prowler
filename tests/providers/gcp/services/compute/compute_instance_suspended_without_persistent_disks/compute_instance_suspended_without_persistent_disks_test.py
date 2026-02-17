from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestComputeInstanceSuspendedWithoutPersistentDisks:

    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()
            assert len(result) == 0

    def test_instance_running_with_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="running-instance",
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
                    status="RUNNING",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance running-instance is not suspended."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "running-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_suspended_with_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="suspended-instance",
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
                    status="SUSPENDED",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance suspended-instance is suspended with 2 persistent disk(s) attached: boot-disk, data-disk."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "suspended-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_suspending_with_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="suspending-instance",
                    id="9876543210",
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
                            name="boot-disk",
                            auto_delete=True,
                            boot=True,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                    status="SUSPENDING",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance suspending-instance is suspending with 1 persistent disk(s) attached: boot-disk."
            )
            assert result[0].resource_id == "9876543210"
            assert result[0].resource_name == "suspending-instance"

    def test_instance_suspended_no_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="suspended-no-disks",
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
                    disks=[],
                    project_id=GCP_PROJECT_ID,
                    status="SUSPENDED",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance suspended-no-disks is suspended but has no persistent disks attached."
            )
            assert result[0].resource_id == "1111111111"
            assert result[0].resource_name == "suspended-no-disks"

    def test_instance_terminated_with_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="terminated-instance",
                    id="2222222222",
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
                    status="TERMINATED",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance terminated-instance is not suspended."
            )
            assert result[0].resource_id == "2222222222"
            assert result[0].resource_name == "terminated-instance"

    def test_multiple_instances_mixed_results(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="running-instance",
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
                    status="RUNNING",
                ),
                Instance(
                    name="suspended-with-disks",
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
                            name="persistent-disk",
                            auto_delete=True,
                            boot=True,
                            encryption=False,
                        ),
                    ],
                    project_id=GCP_PROJECT_ID,
                    status="SUSPENDED",
                ),
                Instance(
                    name="suspended-no-disks",
                    id="3333333333",
                    zone=f"{GCP_US_CENTER1_LOCATION}-c",
                    region=GCP_US_CENTER1_LOCATION,
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    disks=[],
                    project_id=GCP_PROJECT_ID,
                    status="SUSPENDED",
                ),
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 3

            # First instance - RUNNING with disks (PASS)
            assert result[0].status == "PASS"
            assert result[0].resource_name == "running-instance"
            assert "is not suspended" in result[0].status_extended

            # Second instance - SUSPENDED with disks (FAIL)
            assert result[1].status == "FAIL"
            assert result[1].resource_name == "suspended-with-disks"
            assert (
                "is suspended with 1 persistent disk(s) attached"
                in result[1].status_extended
            )

            # Third instance - SUSPENDED without disks (PASS)
            assert result[2].status == "PASS"
            assert result[2].resource_name == "suspended-no-disks"
            assert (
                "is suspended but has no persistent disks attached"
                in result[2].status_extended
            )

    def test_instance_stopping_with_disks(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_suspended_without_persistent_disks.compute_instance_suspended_without_persistent_disks import (
                compute_instance_suspended_without_persistent_disks,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Disk,
                Instance,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.region = GCP_US_CENTER1_LOCATION

            compute_client.instances = [
                Instance(
                    name="stopping-instance",
                    id="4444444444",
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
                    status="STOPPING",
                )
            ]

            check = compute_instance_suspended_without_persistent_disks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance stopping-instance is not suspended."
            )
            assert result[0].resource_id == "4444444444"
            assert result[0].resource_name == "stopping-instance"
