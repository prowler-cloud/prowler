from re import search
from unittest import mock

from tests.providers.gcp.lib.audit_info_utils import GCP_PROJECT_ID


class Test_compute_project_os_login_enabled:
    def test_compute_no_project(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )

            check = compute_project_os_login_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_project(self):
        from prowler.providers.gcp.services.compute.compute_service import Project

        project = Project(
            id=GCP_PROJECT_ID,
            enable_oslogin=True,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = [project]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )

            check = compute_project_os_login_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Project {project.id} has OS Login enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == project.id
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_one_non_compliant_project(self):
        from prowler.providers.gcp.services.compute.compute_service import Project

        project = Project(
            id=GCP_PROJECT_ID,
            enable_oslogin=False,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.projects = [project]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled import (
                compute_project_os_login_enabled,
            )

            check = compute_project_os_login_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Project {project.id} does not have OS Login enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == project.id
            assert result[0].location == "global"
            assert result[0].project_id == GCP_PROJECT_ID
