from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_public_ip:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )

            check = compute_instance_public_ip()
            result = check.execute()
            assert len(result) == 0

    def test_no_public_ip_instance(self):
        compute_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            instance = Instance(
                name="test",
                id="1234567890",
                zone="us-central1-a",
                public_ip=False,
                metadata={},
                shielded_enabled_vtpm=True,
                shielded_enabled_integrity_monitoring=True,
                confidential_computing=True,
                service_accounts=[
                    {"email": "123-compute@developer.gserviceaccount.com"}
                ],
                ip_forward=False,
                disks_encryption=[],
                project_id=GCP_PROJECT_ID,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [instance]

            check = compute_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance test does not have a public IP."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test"
            assert result[0].location == "us-central1-a"

    def test_public_ip_instance(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=True,
            service_accounts=[
                {"email": f"{GCP_PROJECT_ID}-compute@developer.gserviceaccount.com"}
            ],
            ip_forward=True,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_public_ip.compute_instance_public_ip import (
                compute_instance_public_ip,
            )

            check = compute_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "VM Instance test has a public IP."
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test"
            assert result[0].location == "us-central1-a"
