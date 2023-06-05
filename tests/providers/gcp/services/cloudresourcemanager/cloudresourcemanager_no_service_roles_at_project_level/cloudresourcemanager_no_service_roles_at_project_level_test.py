from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_cloudresourcemanager_no_service_roles_at_project_level:
    def test_cloudresourcemanager_no_bindings(self):
        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.bindings = []

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level import (
                cloudresourcemanager_no_service_roles_at_project_level,
            )

            check = cloudresourcemanager_no_service_roles_at_project_level()
            result = check.execute()
            assert len(result) == 0

    def test_three_compliant_binding(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding1 = Binding(
            role="roles/cloudfunctions.serviceAgent",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
        )
        binding2 = Binding(
            role="roles/compute.serviceAgent",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
        )
        binding3 = Binding(
            role="roles/connectors.managedZoneViewer",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_id = GCP_PROJECT_ID
        cloudresourcemanager_client.bindings = [binding1, binding2, binding3]

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level import (
                cloudresourcemanager_no_service_roles_at_project_level,
            )

            check = cloudresourcemanager_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 3
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "No IAM Users assigned to service roles ate project level.",
                    r.status_extended,
                )
                assert r.resource_id == cloudresourcemanager_client.bindings[idx].role

    def test_binding_with_service_account_user(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding = Binding(
            role="roles/iam.serviceAccountUser",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_id = GCP_PROJECT_ID
        cloudresourcemanager_client.bindings = [binding]

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level import (
                cloudresourcemanager_no_service_roles_at_project_level,
            )

            check = cloudresourcemanager_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"IAM Users assigned to service role '{binding.role}' ate project level.",
                result[0].status_extended,
            )
            assert result[0].resource_id == binding.role

    def test_binding_with_service_account_token_creator(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding = Binding(
            role="roles/iam.serviceAccountTokenCreator",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_id = GCP_PROJECT_ID
        cloudresourcemanager_client.bindings = [binding]

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_no_service_roles_at_project_level.cloudresourcemanager_no_service_roles_at_project_level import (
                cloudresourcemanager_no_service_roles_at_project_level,
            )

            check = cloudresourcemanager_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"IAM Users assigned to service role '{binding.role}' ate project level.",
                result[0].status_extended,
            )
            assert result[0].resource_id == binding.role
