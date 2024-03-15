from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_iam_role_kms_enforce_separation_of_duties:
    def test_iam_no_bindings(self):
        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.bindings = []
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties import (
                iam_role_kms_enforce_separation_of_duties,
            )

            check = iam_role_kms_enforce_separation_of_duties()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "Principle of separation of duties was enforced for KMS-Related Roles",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region

    def test_three_compliant_binding(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding1 = Binding(
            role="roles/cloudfunctions.serviceAgent",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )
        binding2 = Binding(
            role="roles/compute.serviceAgent",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )
        binding3 = Binding(
            role="roles/connectors.managedZoneViewer",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.bindings = [binding1, binding2, binding3]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties import (
                iam_role_kms_enforce_separation_of_duties,
            )

            check = iam_role_kms_enforce_separation_of_duties()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "Principle of separation of duties was enforced for KMS-Related Roles",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region

    def test_uncompliant_binding(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding1 = Binding(
            role="roles/cloudkms.admin",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )
        binding2 = Binding(
            role="roles/cloudkms.cryptoKeyEncrypterDecrypter",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )
        binding3 = Binding(
            role="roles/connectors.managedZoneViewer",
            members=["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"],
            project_id=GCP_PROJECT_ID,
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.bindings = [binding1, binding2, binding3]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_kms_enforce_separation_of_duties.iam_role_kms_enforce_separation_of_duties import (
                iam_role_kms_enforce_separation_of_duties,
            )

            check = iam_role_kms_enforce_separation_of_duties()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert search(
                    "Principle of separation of duties was not enforced for KMS-Related Roles",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region
