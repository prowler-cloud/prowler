from unittest import mock

from prowler.providers.vercel.services.project.project_service import VercelProject
from tests.providers.vercel.vercel_fixtures import (
    PROJECT_ID,
    PROJECT_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)

CHECK_PATH = "prowler.providers.vercel.services.project.project_linked_to_git_repository.project_linked_to_git_repository"


def _run(project_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_vercel_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.project_client", new=project_client),
    ):
        from prowler.providers.vercel.services.project.project_linked_to_git_repository.project_linked_to_git_repository import (
            project_linked_to_git_repository,
        )

        return project_linked_to_git_repository().execute()


class Test_project_linked_to_git_repository:
    def test_no_projects(self):
        project_client = mock.MagicMock
        project_client.projects = {}

        assert len(_run(project_client)) == 0

    def test_project_linked(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                git_repository={
                    "type": "github",
                    "repo": "acme/storefront",
                    "repoId": 123456,
                    "productionBranch": "main",
                },
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].resource_id == PROJECT_ID
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} is linked to the github repository acme/storefront, so deployments are traceable to commits."
        )
        assert result[0].team_id == TEAM_ID

    def test_project_not_linked(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                git_repository=None,
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} is not linked to a Git repository, so deployments can be pushed from any workstation without code review or commit history."
        )

    def test_project_with_empty_link(self):
        project_client = mock.MagicMock
        project_client.projects = {
            PROJECT_ID: VercelProject(
                id=PROJECT_ID,
                name=PROJECT_NAME,
                team_id=TEAM_ID,
                git_repository={},
            )
        }

        result = _run(project_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
