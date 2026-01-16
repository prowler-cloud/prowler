from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestComputeInstanceDesiredMachineType:
    def test_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []
        compute_client.audit_config = {"desired_machine_types": ["n2-standard-4"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )

            check = compute_instance_desired_machine_type()
            result = check.execute()
            assert len(result) == 0

    def test_instance_with_approved_machine_type(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {
                "desired_machine_types": ["n2-standard-4", "e2-medium", "c2-standard-4"]
            }
            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="n2-standard-4",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "approved machine type" in result[0].status_extended
            assert "n2-standard-4" in result[0].status_extended
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test-instance"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_with_unapproved_machine_type(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {
                "desired_machine_types": ["n2-standard-4", "e2-medium"]
            }
            compute_client.instances = [
                Instance(
                    name="test-instance-wrong-type",
                    id="0987654321",
                    zone="us-east1-b",
                    region="us-east1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="n1-standard-1",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not in the approved list" in result[0].status_extended
            assert "n1-standard-1" in result[0].status_extended
            assert result[0].resource_id == "0987654321"
            assert result[0].resource_name == "test-instance-wrong-type"

    def test_no_desired_machine_types_configured(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"desired_machine_types": []}
            compute_client.instances = [
                Instance(
                    name="test-instance-no-config",
                    id="1111111111",
                    zone="europe-west1-b",
                    region="europe-west1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="e2-micro",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not evaluated" in result[0].status_extended
            assert "no desired machine types configured" in result[0].status_extended

    def test_default_when_not_configured(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {}  # No desired_machine_types key
            compute_client.instances = [
                Instance(
                    name="test-instance-default",
                    id="2222222222",
                    zone="asia-east1-a",
                    region="asia-east1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="f1-micro",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "not evaluated" in result[0].status_extended

    def test_multiple_instances_mixed_results(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {
                "desired_machine_types": ["n2-standard-4", "c2-standard-4"]
            }
            compute_client.instances = [
                Instance(
                    name="approved-instance",
                    id="3333333333",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="n2-standard-4",
                ),
                Instance(
                    name="unapproved-instance",
                    id="4444444444",
                    zone="us-central1-b",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="e2-small",
                ),
                Instance(
                    name="another-approved-instance",
                    id="5555555555",
                    zone="us-central1-c",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="c2-standard-4",
                ),
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 3

            approved_result = next(r for r in result if r.resource_id == "3333333333")
            unapproved_result = next(r for r in result if r.resource_id == "4444444444")
            another_approved_result = next(
                r for r in result if r.resource_id == "5555555555"
            )

            assert approved_result.status == "PASS"
            assert approved_result.resource_name == "approved-instance"

            assert unapproved_result.status == "FAIL"
            assert unapproved_result.resource_name == "unapproved-instance"

            assert another_approved_result.status == "PASS"
            assert another_approved_result.resource_name == "another-approved-instance"

    def test_instance_with_custom_machine_type(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {
                "desired_machine_types": ["custom-4-16384", "n2-standard-4"]
            }
            compute_client.instances = [
                Instance(
                    name="custom-machine-instance",
                    id="6666666666",
                    zone="us-west1-a",
                    region="us-west1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="custom-4-16384",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "custom-4-16384" in result[0].status_extended

    def test_gke_managed_instance(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {"desired_machine_types": ["n2-standard-4"]}
            compute_client.instances = [
                Instance(
                    name="gke-my-cluster-default-pool-abc123",
                    id="7777777777",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="e2-medium",
                )
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "GKE-managed node" in result[0].status_extended
            assert "Manual review recommended" in result[0].status_extended

    def test_regex_pattern_matching(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_desired_machine_type.compute_instance_desired_machine_type import (
                compute_instance_desired_machine_type,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.audit_config = {
                "desired_machine_types": ["^n2-.*", ".*-standard-4$"]
            }
            compute_client.instances = [
                Instance(
                    name="regex-test-1",
                    id="8888888888",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="n2-standard-8",
                ),
                Instance(
                    name="regex-test-2",
                    id="9999999999",
                    zone="us-central1-b",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="c2-standard-4",
                ),
                Instance(
                    name="regex-test-3",
                    id="1010101010",
                    zone="us-central1-c",
                    region="us-central1",
                    public_ip=False,
                    project_id=GCP_PROJECT_ID,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    machine_type="e2-micro",
                ),
            ]

            check = compute_instance_desired_machine_type()
            result = check.execute()

            assert len(result) == 3

            n2_result = next(r for r in result if r.resource_id == "8888888888")
            assert n2_result.status == "PASS"
            assert "n2-standard-8" in n2_result.status_extended

            c2_result = next(r for r in result if r.resource_id == "9999999999")
            assert c2_result.status == "PASS"
            assert "c2-standard-4" in c2_result.status_extended

            e2_result = next(r for r in result if r.resource_id == "1010101010")
            assert e2_result.status == "FAIL"
            assert "e2-micro" in e2_result.status_extended
