from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_iam_no_service_roles_at_project_level:
    def test_iam_no_bindings(self):
        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.bindings = []
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service.CloudResourceManager",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level import (
                iam_no_service_roles_at_project_level,
            )

            check = iam_no_service_roles_at_project_level()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "No IAM Users assigned to service roles at project level",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID

    def test_three_compliant_binding(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding1 = Binding(
            role="roles/cloudfunctions.serviceAgent",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
            project_id=GCP_PROJECT_ID,
        )
        binding2 = Binding(
            role="roles/compute.serviceAgent",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
            project_id=GCP_PROJECT_ID,
        )
        binding3 = Binding(
            role="roles/connectors.managedZoneViewer",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
            project_id=GCP_PROJECT_ID,
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.bindings = [binding1, binding2, binding3]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service.CloudResourceManager",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level import (
                iam_no_service_roles_at_project_level,
            )

            check = iam_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "PASS"
            assert search(
                "No IAM Users assigned to service roles at project level",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == ""
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == cloudresourcemanager_client.region

    def test_binding_with_service_account_user(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding = Binding(
            role="roles/iam.serviceAccountUser",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
            project_id=GCP_PROJECT_ID,
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.bindings = [binding]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service.CloudResourceManager",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level import (
                iam_no_service_roles_at_project_level,
            )

            check = iam_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"IAM Users assigned to service role '{binding.role}' at project level",
                result[0].status_extended,
            )
            assert result[0].resource_id == binding.role
            assert result[0].resource_name == binding.role
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == cloudresourcemanager_client.region

    def test_binding_with_service_account_token_creator(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Binding,
        )

        binding = Binding(
            role="roles/iam.serviceAccountTokenCreator",
            members=[["serviceAccount:685829395199@cloudbuild.gserviceaccount.com"]],
            project_id=GCP_PROJECT_ID,
        )

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.bindings = [binding]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service.CloudResourceManager",
            new=cloudresourcemanager_client,
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_no_service_roles_at_project_level.iam_no_service_roles_at_project_level import (
                iam_no_service_roles_at_project_level,
            )

            check = iam_no_service_roles_at_project_level()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"IAM Users assigned to service role '{binding.role}' at project level {GCP_PROJECT_ID}",
                result[0].status_extended,
            )
            assert result[0].resource_id == binding.role
            assert result[0].resource_name == binding.role
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == cloudresourcemanager_client.region
