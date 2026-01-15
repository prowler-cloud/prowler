from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestComputeInstanceDeletionProtectionEnabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled import (
                compute_instance_deletion_protection_enabled,
            )

            check = compute_instance_deletion_protection_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_deletion_protection_enabled(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled import (
                compute_instance_deletion_protection_enabled,
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
                    project_id=GCP_PROJECT_ID,
                    deletion_protection=True,
                )
            ]

            check = compute_instance_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} has deletion protection enabled."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_deletion_protection_disabled(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_deletion_protection_enabled.compute_instance_deletion_protection_enabled import (
                compute_instance_deletion_protection_enabled,
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
                        {
                            "email": f"{GCP_PROJECT_ID}-compute@developer.gserviceaccount.com"
                        }
                    ],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    deletion_protection=False,
                )
            ]

            check = compute_instance_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} does not have deletion protection enabled."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
