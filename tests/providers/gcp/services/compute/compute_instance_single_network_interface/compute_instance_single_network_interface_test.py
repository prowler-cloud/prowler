from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_single_network_interface:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )

            check = compute_instance_single_network_interface()
            result = check.execute()
            assert len(result) == 0

    def test_single_network_interface(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )
            from prowler.providers.gcp.services.compute.compute_service import (
                Instance,
                NetworkInterface,
            )

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
                service_accounts=[
                    {"email": "123-compute@developer.gserviceaccount.com"}
                ],
                ip_forward=False,
                disks_encryption=[],
                project_id=GCP_PROJECT_ID,
                network_interfaces=[
                    NetworkInterface(
                        name="nic0", network="default", subnetwork="default"
                    )
                ],
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [instance]

            check = compute_instance_single_network_interface()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has a single network interface: nic0."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "test-instance"
            assert result[0].location == "us-central1"

    def test_multiple_network_interfaces(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Instance,
            NetworkInterface,
        )

        instance = Instance(
            name="multi-nic-instance",
            id="9876543210",
            zone="us-central1-a",
            region="us-central1",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[
                {"email": f"{GCP_PROJECT_ID}-compute@developer.gserviceaccount.com"}
            ],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            network_interfaces=[
                NetworkInterface(name="nic0", network="default", subnetwork="subnet-1"),
                NetworkInterface(name="nic1", network="vpc-2", subnetwork="subnet-2"),
                NetworkInterface(name="nic2", network="vpc-3", subnetwork="subnet-3"),
            ],
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )

            check = compute_instance_single_network_interface()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance multi-nic-instance has 3 network interfaces: nic0, nic1, nic2."
            )
            assert result[0].resource_id == "9876543210"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "multi-nic-instance"
            assert result[0].location == "us-central1"

    def test_two_network_interfaces(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Instance,
            NetworkInterface,
        )

        instance = Instance(
            name="dual-nic-instance",
            id="1111111111",
            zone="europe-west1-b",
            region="europe-west1",
            public_ip=False,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            network_interfaces=[
                NetworkInterface(name="nic0", network="default", subnetwork="default"),
                NetworkInterface(name="nic1", network="vpc-2", subnetwork="subnet-2"),
            ],
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )

            check = compute_instance_single_network_interface()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance dual-nic-instance has 2 network interfaces: nic0, nic1."
            )
            assert result[0].resource_id == "1111111111"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "dual-nic-instance"
            assert result[0].location == "europe-west1"

    def test_mixed_instances(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Instance,
            NetworkInterface,
        )

        instance_single_nic = Instance(
            name="single-nic-instance",
            id="1111111111",
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
            network_interfaces=[
                NetworkInterface(name="nic0", network="default", subnetwork="default")
            ],
        )

        instance_multi_nic = Instance(
            name="multi-nic-instance",
            id="2222222222",
            zone="us-central1-a",
            region="us-central1",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[],
            project_id=GCP_PROJECT_ID,
            network_interfaces=[
                NetworkInterface(name="nic0", network="default", subnetwork="default"),
                NetworkInterface(name="nic1", network="vpc-2", subnetwork="subnet-2"),
                NetworkInterface(name="nic2", network="vpc-3", subnetwork="subnet-3"),
                NetworkInterface(name="nic3", network="vpc-4", subnetwork="subnet-4"),
            ],
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance_single_nic, instance_multi_nic]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )

            check = compute_instance_single_network_interface()
            result = check.execute()

            assert len(result) == 2

            # First instance: single NIC (PASS)
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance single-nic-instance has a single network interface: nic0."
            )
            assert result[0].resource_id == "1111111111"
            assert result[0].resource_name == "single-nic-instance"

            # Second instance: multiple NICs (FAIL)
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "VM Instance multi-nic-instance has 4 network interfaces: nic0, nic1, nic2, nic3."
            )
            assert result[1].resource_id == "2222222222"
            assert result[1].resource_name == "multi-nic-instance"

    def test_gke_instance_multiple_network_interfaces(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Instance,
            NetworkInterface,
        )

        instance = Instance(
            name="gke-cluster-default-pool-12345678-abcd",
            id="9999999999",
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
            network_interfaces=[
                NetworkInterface(
                    name="nic0", network="gke-network", subnetwork="gke-subnet"
                ),
                NetworkInterface(
                    name="nic1", network="gke-network-2", subnetwork="gke-subnet-2"
                ),
            ],
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_single_network_interface.compute_instance_single_network_interface import (
                compute_instance_single_network_interface,
            )

            check = compute_instance_single_network_interface()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == "VM Instance gke-cluster-default-pool-12345678-abcd has 2 network interfaces: nic0, nic1. This is a GKE-managed instance which may legitimately require multiple interfaces. Manual review recommended."
            )
            assert result[0].resource_id == "9999999999"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "gke-cluster-default-pool-12345678-abcd"
            assert result[0].location == "us-central1"
