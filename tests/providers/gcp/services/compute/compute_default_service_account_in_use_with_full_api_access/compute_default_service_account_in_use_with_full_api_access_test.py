from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_compute_default_service_account_in_use_with_full_api_access:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access import (
                compute_default_service_account_in_use_with_full_api_access,
            )

            check = compute_default_service_account_in_use_with_full_api_access()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[
                {"email": "123-compute@developer.gserviceaccount.com", "scopes": []}
            ],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access import (
                compute_default_service_account_in_use_with_full_api_access,
            )

            check = compute_default_service_account_in_use_with_full_api_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"The VM Instance {instance.name} is not configured to use the default service account with full access to all cloud APIs ",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_compliant_instance_gke(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="gke-test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[
                {
                    "email": f"{GCP_PROJECT_ID}-compute@developer.gserviceaccount.com",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access import (
                compute_default_service_account_in_use_with_full_api_access,
            )

            check = compute_default_service_account_in_use_with_full_api_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"The VM Instance {instance.name} is not configured to use the default service account with full access to all cloud APIs ",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_instance_with_default_service_account(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[
                {
                    "email": f"{GCP_PROJECT_ID}-compute@developer.gserviceaccount.com",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_default_service_account_in_use_with_full_api_access.compute_default_service_account_in_use_with_full_api_access import (
                compute_default_service_account_in_use_with_full_api_access,
            )

            check = compute_default_service_account_in_use_with_full_api_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"The VM Instance {instance.name} is configured to use the default service account with full access to all cloud APIs ",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
