from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.githubactions.githubactions_service import (
    GithubActionsWorkflowFinding,
)
from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


def _make_repo(repo_id=1, name="repo1", owner="account-name"):
    return Repo(
        id=repo_id,
        name=name,
        owner=owner,
        full_name=f"{owner}/{name}",
        default_branch=Branch(
            name="main",
            protected=False,
            default_branch=True,
            require_pull_request=False,
            approval_count=0,
            required_linear_history=False,
            allow_force_pushes=True,
            branch_deletion=True,
            status_checks=False,
            enforce_admins=False,
            require_code_owner_reviews=False,
            require_signed_commits=False,
            conversation_resolution=False,
        ),
        private=False,
        securitymd=True,
        codeowners_exists=False,
        secret_scanning_enabled=True,
        archived=False,
        pushed_at=datetime.now(timezone.utc),
        delete_branch_on_merge=False,
    )


def _make_finding(
    repo_id=1,
    repo_name="repo1",
    repo_owner="account-name",
    workflow_file=".github/workflows/ci.yml",
):
    return GithubActionsWorkflowFinding(
        repo_id=repo_id,
        repo_name=repo_name,
        repo_full_name=f"{repo_owner}/{repo_name}",
        repo_owner=repo_owner,
        workflow_file=workflow_file,
        workflow_url=f"https://github.com/{repo_owner}/{repo_name}/blob/main/{workflow_file}",
        line_range="line 10",
        finding_id="githubactions_template_injection",
        ident="template-injection",
        description="Template Injection Vulnerability",
        severity="high",
        confidence="High",
        annotation="High risk of code execution",
        url="https://docs.zizmor.sh/",
    )


class Test_githubactions_workflow_security_scan:
    def test_no_repositories(self):
        repository_client = mock.MagicMock()
        repository_client.repositories = {}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 0

    def test_repository_no_findings_pass(self):
        repo = _make_repo()
        repository_client = mock.MagicMock()
        repository_client.repositories = {1: repo}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "repo1"
            assert (
                result[0].check_metadata.CheckID
                == "githubactions_workflow_security_scan"
            )
            assert (
                "no GitHub Actions workflow security issues"
                in result[0].status_extended
            )

    def test_repository_with_findings_fail(self):
        repo = _make_repo()
        finding = _make_finding()

        repository_client = mock.MagicMock()
        repository_client.repositories = {1: repo}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {1: [finding]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == ".github/workflows/ci.yml"
            assert "Template Injection Vulnerability" in result[0].status_extended
            assert "line 10" in result[0].status_extended
            assert "High" in result[0].status_extended
            assert (
                "https://github.com/account-name/repo1/blob/main/.github/workflows/ci.yml"
                in result[0].status_extended
            )
            assert (
                result[0].check_metadata.CheckID == "githubactions_template_injection"
            )
            assert (
                result[0].check_metadata.CheckTitle
                == "GitHub Actions workflow template-injection detected by zizmor"
            )
            assert result[0].check_metadata.Severity == "high"
            assert result[0].check_metadata.Risk == "Template Injection Vulnerability"
            assert "https://docs.zizmor.sh/" in result[0].check_metadata.AdditionalURLs

    def test_repository_with_multiple_findings(self):
        repo = _make_repo()
        finding1 = _make_finding(workflow_file=".github/workflows/ci.yml")
        finding2 = _make_finding(workflow_file=".github/workflows/deploy.yml")

        repository_client = mock.MagicMock()
        repository_client.repositories = {1: repo}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {1: [finding1, finding2]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 2
            assert all(r.status == "FAIL" for r in result)
            workflow_files = [r.resource_name for r in result]
            assert ".github/workflows/ci.yml" in workflow_files
            assert ".github/workflows/deploy.yml" in workflow_files

    def test_findings_have_independent_metadata(self):
        repo = _make_repo()
        finding1 = GithubActionsWorkflowFinding(
            repo_id=1,
            repo_name="repo1",
            repo_full_name="account-name/repo1",
            repo_owner="account-name",
            workflow_file=".github/workflows/ci.yml",
            workflow_url="https://github.com/account-name/repo1/blob/main/.github/workflows/ci.yml",
            line_range="line 10",
            finding_id="githubactions_template_injection",
            ident="template-injection",
            description="Template Injection",
            severity="high",
            confidence="High",
            annotation="Attacker-controllable code",
            url="https://docs.zizmor.sh/audits/#template-injection",
        )
        finding2 = GithubActionsWorkflowFinding(
            repo_id=1,
            repo_name="repo1",
            repo_full_name="account-name/repo1",
            repo_owner="account-name",
            workflow_file=".github/workflows/deploy.yml",
            workflow_url="https://github.com/account-name/repo1/blob/main/.github/workflows/deploy.yml",
            line_range="line 5",
            finding_id="githubactions_excessive_permissions",
            ident="excessive-permissions",
            description="Excessive Permissions",
            severity="medium",
            confidence="Medium",
            annotation="Workflow has overly broad permissions",
            url="https://docs.zizmor.sh/audits/#excessive-permissions",
        )

        repository_client = mock.MagicMock()
        repository_client.repositories = {1: repo}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {1: [finding1, finding2]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 2

            r1 = next(
                r for r in result if r.resource_name == ".github/workflows/ci.yml"
            )
            r2 = next(
                r for r in result if r.resource_name == ".github/workflows/deploy.yml"
            )

            assert r1.check_metadata.CheckID == "githubactions_template_injection"
            assert r1.check_metadata.Severity == "high"
            assert r1.check_metadata.Risk == "Template Injection"
            assert (
                "https://docs.zizmor.sh/audits/#template-injection"
                in r1.check_metadata.AdditionalURLs
            )

            assert r2.check_metadata.CheckID == "githubactions_excessive_permissions"
            assert r2.check_metadata.Severity == "medium"
            assert r2.check_metadata.Risk == "Excessive Permissions"
            assert (
                "https://docs.zizmor.sh/audits/#excessive-permissions"
                in r2.check_metadata.AdditionalURLs
            )

    def test_multiple_repos_mixed(self):
        repo1 = _make_repo(repo_id=1, name="repo1")
        repo2 = _make_repo(repo_id=2, name="repo2")
        finding = _make_finding(repo_id=1)

        repository_client = mock.MagicMock()
        repository_client.repositories = {1: repo1, 2: repo2}

        githubactions_client = mock.MagicMock()
        githubactions_client.findings = {1: [finding]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.repository_client",
                new=repository_client,
            ),
            mock.patch(
                "prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan.githubactions_client",
                new=githubactions_client,
            ),
        ):
            from prowler.providers.github.services.githubactions.githubactions_workflow_security_scan.githubactions_workflow_security_scan import (
                githubactions_workflow_security_scan,
            )

            check = githubactions_workflow_security_scan()
            result = check.execute()
            assert len(result) == 2
            statuses = {r.resource_name: r.status for r in result}
            assert statuses[".github/workflows/ci.yml"] == "FAIL"
            assert statuses["repo2"] == "PASS"
