from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_iam_role_sa_enforce_separation_of_duties:
    def test_iam_no_bindings(self):
        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.bindings = []
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties import (
                iam_role_sa_enforce_separation_of_duties,
            )

            check = iam_role_sa_enforce_separation_of_duties()
            result = check.execute()
            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "Principle of separation of duties was enforced for Service-Account Related Roles",
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
            "prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties import (
                iam_role_sa_enforce_separation_of_duties,
            )

            check = iam_role_sa_enforce_separation_of_duties()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "Principle of separation of duties was enforced for Service-Account Related Roles",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region

    def test_one_uncompliant_binding(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding1 = Binding(
            role="roles/iam.serviceAccountUser",
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
            "prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_role_sa_enforce_separation_of_duties.iam_role_sa_enforce_separation_of_duties import (
                iam_role_sa_enforce_separation_of_duties,
            )

            check = iam_role_sa_enforce_separation_of_duties()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert search(
                    "Principle of separation of duties was not enforced for Service-Account Related Roles",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region
