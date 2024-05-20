from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_iam_audit_logs_enabled:
    def test_iam_no_projects(self):
        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.projects = []
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled import (
                iam_audit_logs_enabled,
            )

            check = iam_audit_logs_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_compliant_project(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Project,
        )

        project1 = Project(id=GCP_PROJECT_ID, audit_logging=True)

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.projects = [project1]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled import (
                iam_audit_logs_enabled,
            )

            check = iam_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "PASS"
                assert search(
                    "Audit Logs are enabled for project",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region

    def test_uncompliant_project(self):
        from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
            Project,
        )

        project1 = Project(id=GCP_PROJECT_ID, audit_logging=False)

        cloudresourcemanager_client = mock.MagicMock
        cloudresourcemanager_client.project_ids = [GCP_PROJECT_ID]
        cloudresourcemanager_client.projects = [project1]
        cloudresourcemanager_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled.cloudresourcemanager_client",
            new=cloudresourcemanager_client,
        ):
            from prowler.providers.gcp.services.iam.iam_audit_logs_enabled.iam_audit_logs_enabled import (
                iam_audit_logs_enabled,
            )

            check = iam_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            for idx, r in enumerate(result):
                assert r.status == "FAIL"
                assert search(
                    "Audit Logs are not enabled for project",
                    r.status_extended,
                )
                assert r.resource_id == GCP_PROJECT_ID
                assert r.project_id == GCP_PROJECT_ID
                assert r.location == cloudresourcemanager_client.region
