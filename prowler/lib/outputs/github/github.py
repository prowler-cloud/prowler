"""GitHub Integration Module."""

import os
from dataclasses import dataclass
from typing import Dict, List

import requests

from prowler.lib.logger import logger
from prowler.lib.outputs.github.exceptions.exceptions import (
    GitHubAuthenticationError,
    GitHubGetLabelsError,
    GitHubGetLabelsResponseError,
    GitHubGetRepositoriesError,
    GitHubGetRepositoriesResponseError,
    GitHubInvalidParameterError,
    GitHubInvalidRepositoryError,
    GitHubNoRepositoriesError,
    GitHubTestConnectionError,
)
from prowler.providers.common.models import Connection


@dataclass
class GitHubConnection(Connection):
    """
    Represents a GitHub connection object.
    Attributes:
        repositories (dict): Dictionary of repositories in GitHub.
    """

    repositories: dict = None


class GitHub:
    """
    GitHub class to interact with the GitHub API

    This integration supports creating GitHub Issues from Prowler findings.
    It uses Personal Access Token (PAT) authentication.

    Attributes:
        - _token: The Personal Access Token
        - _owner: The repository owner (user or organization)
        - _api_url: The GitHub API base URL (defaults to https://api.github.com)

    Methods:
        - __init__: Initialize the GitHub object
        - test_connection: Test the connection to GitHub and return a Connection object
        - get_repositories: Get the accessible repositories from GitHub
        - get_repository_labels: Get the available labels for a repository
        - send_finding: Send a finding to GitHub and create an issue

    Raises:
        - GitHubAuthenticationError: Failed to authenticate
        - GitHubTokenError: Token is invalid or missing
        - GitHubNoRepositoriesError: No repositories found
        - GitHubGetRepositoriesError: Failed to get repositories
        - GitHubGetRepositoriesResponseError: Failed to get repositories, response code did not match 200
        - GitHubInvalidRepositoryError: The repository is invalid
        - GitHubCreateIssueError: Failed to create an issue
        - GitHubCreateIssueResponseError: Failed to create an issue, response code did not match 201
        - GitHubTestConnectionError: Failed to test the connection
        - GitHubInvalidParameterError: Invalid parameters provided
        - GitHubGetLabelsError: Failed to get labels
        - GitHubGetLabelsResponseError: Failed to get labels, response code did not match 200

    Usage:
        github = GitHub(
            token="ghp_xxxxxxxxxxxx",
            owner="myorg"
        )
        github.send_finding(
            check_id="aws_ec2_instance_public_ip",
            severity="high",
            repository="myorg/myrepo",
            ...
        )
    """

    _token: str = None
    _owner: str = None
    _api_url: str = "https://api.github.com"
    HEADER_TEMPLATE = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def __init__(
        self,
        token: str = None,
        owner: str = None,
        api_url: str = None,
    ):
        """
        Initialize the GitHub client.

        Args:
            token: GitHub Personal Access Token
            owner: Repository owner (user or organization)
            api_url: GitHub API base URL (defaults to https://api.github.com for GitHub.com,
                    use https://github.example.com/api/v3 for GitHub Enterprise)
        """
        if not token:
            raise GitHubInvalidParameterError(
                message="GitHub token is required",
                file=os.path.basename(__file__),
            )

        self._token = token
        self._owner = owner
        if api_url:
            self._api_url = api_url.rstrip("/")

        # Test authentication
        try:
            self._authenticate()
        except Exception as e:
            raise GitHubAuthenticationError(
                message=f"Failed to authenticate with GitHub: {str(e)}",
                file=os.path.basename(__file__),
            )

    def _get_headers(self) -> Dict:
        """Get the headers for GitHub API requests."""
        headers = self.HEADER_TEMPLATE.copy()
        headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _authenticate(self) -> bool:
        """
        Authenticate with GitHub by testing the token.

        Returns:
            True if authentication successful

        Raises:
            GitHubAuthenticationError: If authentication fails
        """
        try:
            response = requests.get(
                f"{self._api_url}/user",
                headers=self._get_headers(),
                timeout=10,
            )
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                raise GitHubAuthenticationError(
                    message="Invalid or expired GitHub token",
                    file=os.path.basename(__file__),
                )
            else:
                raise GitHubAuthenticationError(
                    message=f"GitHub authentication failed with status {response.status_code}",
                    file=os.path.basename(__file__),
                )
        except requests.exceptions.RequestException as e:
            raise GitHubAuthenticationError(
                message=f"Failed to connect to GitHub: {str(e)}",
                file=os.path.basename(__file__),
            )

    @staticmethod
    def test_connection(
        token: str = None,
        owner: str = None,
        api_url: str = None,
        raise_on_exception: bool = True,
    ) -> GitHubConnection:
        """
        Test the connection to GitHub.

        Args:
            token: GitHub Personal Access Token
            owner: Repository owner (optional)
            api_url: GitHub API base URL (optional)
            raise_on_exception: Whether to raise exceptions or return error in Connection object

        Returns:
            GitHubConnection object with connection status and repositories
        """
        try:
            github = GitHub(token=token, owner=owner, api_url=api_url)
            repositories = github.get_repositories()
            return GitHubConnection(
                is_connected=True,
                error=None,
                repositories=repositories,
            )
        except Exception as e:
            logger.error(f"GitHub connection test failed: {str(e)}")
            if raise_on_exception:
                raise GitHubTestConnectionError(
                    message=f"Failed to test GitHub connection: {str(e)}",
                    file=os.path.basename(__file__),
                )
            return GitHubConnection(
                is_connected=False,
                error=str(e),
                repositories={},
            )

    def get_repositories(self) -> Dict[str, str]:
        """
        Get accessible repositories from GitHub.

        Returns:
            Dictionary with repository full names as keys and names as values
            Example: {"owner/repo1": "repo1", "owner/repo2": "repo2"}

        Raises:
            GitHubGetRepositoriesError: If getting repositories fails
            GitHubGetRepositoriesResponseError: If response is invalid
            GitHubNoRepositoriesError: If no repositories found
        """
        try:
            repositories = {}
            page = 1
            per_page = 100

            while True:
                # Get repositories for the authenticated user
                response = requests.get(
                    f"{self._api_url}/user/repos",
                    headers=self._get_headers(),
                    params={
                        "per_page": per_page,
                        "page": page,
                        "sort": "updated",
                        "affiliation": "owner,collaborator,organization_member",
                    },
                    timeout=10,
                )

                if response.status_code != 200:
                    raise GitHubGetRepositoriesResponseError(
                        message=f"Failed to get repositories: {response.status_code} - {response.text}",
                        file=os.path.basename(__file__),
                    )

                repos = response.json()
                if not repos:
                    break

                for repo in repos:
                    full_name = repo.get("full_name")
                    name = repo.get("name")
                    if full_name and name:
                        repositories[full_name] = name

                # Check if there are more pages
                if len(repos) < per_page:
                    break
                page += 1

            if not repositories:
                raise GitHubNoRepositoriesError(
                    message="No repositories found for the authenticated user",
                    file=os.path.basename(__file__),
                )

            return repositories

        except GitHubNoRepositoriesError:
            raise
        except GitHubGetRepositoriesResponseError:
            raise
        except Exception as e:
            raise GitHubGetRepositoriesError(
                message=f"Failed to get repositories: {str(e)}",
                file=os.path.basename(__file__),
            )

    def get_repository_labels(self, repository: str) -> List[str]:
        """
        Get available labels for a repository.

        Args:
            repository: Repository full name (e.g., "owner/repo")

        Returns:
            List of label names

        Raises:
            GitHubGetLabelsError: If getting labels fails
            GitHubGetLabelsResponseError: If response is invalid
        """
        try:
            response = requests.get(
                f"{self._api_url}/repos/{repository}/labels",
                headers=self._get_headers(),
                params={"per_page": 100},
                timeout=10,
            )

            if response.status_code != 200:
                raise GitHubGetLabelsResponseError(
                    message=f"Failed to get labels: {response.status_code} - {response.text}",
                    file=os.path.basename(__file__),
                )

            labels = response.json()
            return [label.get("name") for label in labels if label.get("name")]

        except GitHubGetLabelsResponseError:
            raise
        except Exception as e:
            raise GitHubGetLabelsError(
                message=f"Failed to get repository labels: {str(e)}",
                file=os.path.basename(__file__),
            )

    @staticmethod
    def _get_severity_label(severity: str) -> str:
        """Get a severity label with color indicator."""
        severity_lower = severity.lower()
        emoji_map = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "informational": "🔵",
        }
        emoji = emoji_map.get(severity_lower, "⚪")
        return f"{emoji} {severity.upper()}"

    @staticmethod
    def _get_status_label(status: str) -> str:
        """Get a status label with indicator."""
        status_lower = status.lower()
        if "fail" in status_lower:
            return "❌ FAIL"
        elif "pass" in status_lower:
            return "✅ PASS"
        else:
            return f"ℹ️ {status.upper()}"

    def _build_issue_body(
        self,
        check_id: str = "",
        check_title: str = "",
        severity: str = "",
        status: str = "",
        status_extended: str = "",
        provider: str = "",
        region: str = "",
        resource_uid: str = "",
        resource_name: str = "",
        risk: str = "",
        recommendation_text: str = "",
        recommendation_url: str = "",
        remediation_code_native_iac: str = "",
        remediation_code_terraform: str = "",
        remediation_code_cli: str = "",
        remediation_code_other: str = "",
        resource_tags: dict = None,
        compliance: dict = None,
        finding_url: str = "",
        tenant_info: str = "",
    ) -> str:
        """
        Build the markdown body for the GitHub issue.

        GitHub natively supports markdown, so we can use standard markdown formatting.
        """
        body_parts = []

        # Header with severity and status
        body_parts.append("## Prowler Security Finding\n")

        # Metadata table
        body_parts.append("### Finding Details\n")
        body_parts.append("| Field | Value |")
        body_parts.append("|-------|-------|")

        if check_id:
            body_parts.append(f"| **Check ID** | `{check_id}` |")
        if check_title:
            body_parts.append(f"| **Check Title** | {check_title} |")
        if severity:
            body_parts.append(
                f"| **Severity** | {self._get_severity_label(severity)} |"
            )
        if status:
            body_parts.append(f"| **Status** | {self._get_status_label(status)} |")
        if status_extended:
            body_parts.append(f"| **Status Details** | {status_extended} |")
        if provider:
            body_parts.append(f"| **Provider** | {provider.upper()} |")
        if region:
            body_parts.append(f"| **Region** | {region} |")
        if resource_uid:
            body_parts.append(f"| **Resource UID** | `{resource_uid}` |")
        if resource_name:
            body_parts.append(f"| **Resource Name** | {resource_name} |")
        if tenant_info:
            body_parts.append(f"| **Tenant** | {tenant_info} |")

        body_parts.append("")

        # Risk description
        if risk:
            body_parts.append("### Risk\n")
            body_parts.append(risk)
            body_parts.append("")

        # Recommendation
        if recommendation_text or recommendation_url:
            body_parts.append("### Recommendation\n")
            if recommendation_text:
                body_parts.append(recommendation_text)
            if recommendation_url:
                body_parts.append(f"\n[View Recommendation]({recommendation_url})")
            body_parts.append("")

        # Remediation code
        if any(
            [
                remediation_code_native_iac,
                remediation_code_terraform,
                remediation_code_cli,
                remediation_code_other,
            ]
        ):
            body_parts.append("### Remediation\n")

            if remediation_code_cli:
                body_parts.append("#### CLI")
                body_parts.append("```bash")
                body_parts.append(remediation_code_cli.strip())
                body_parts.append("```\n")

            if remediation_code_terraform:
                body_parts.append("#### Terraform")
                body_parts.append("```hcl")
                body_parts.append(remediation_code_terraform.strip())
                body_parts.append("```\n")

            if remediation_code_native_iac:
                body_parts.append("#### Native IaC")
                body_parts.append("```yaml")
                body_parts.append(remediation_code_native_iac.strip())
                body_parts.append("```\n")

            if remediation_code_other:
                body_parts.append("#### Other")
                body_parts.append("```")
                body_parts.append(remediation_code_other.strip())
                body_parts.append("```\n")

        # Resource tags
        if resource_tags:
            body_parts.append("### Resource Tags\n")
            for key, value in resource_tags.items():
                body_parts.append(f"- **{key}**: {value}")
            body_parts.append("")

        # Compliance
        if compliance:
            body_parts.append("### Compliance Frameworks\n")
            for framework, requirements in compliance.items():
                if requirements:
                    body_parts.append(f"- **{framework}**: {', '.join(requirements)}")
            body_parts.append("")

        # Finding URL
        if finding_url:
            body_parts.append(f"[View Finding in Prowler]({finding_url})\n")

        # Footer
        body_parts.append("---")
        body_parts.append("*This issue was automatically created by Prowler*")

        return "\n".join(body_parts)

    def send_finding(
        self,
        check_id: str = "",
        check_title: str = "",
        severity: str = "",
        status: str = "",
        status_extended: str = "",
        provider: str = "",
        region: str = "",
        resource_uid: str = "",
        resource_name: str = "",
        risk: str = "",
        recommendation_text: str = "",
        recommendation_url: str = "",
        remediation_code_native_iac: str = "",
        remediation_code_terraform: str = "",
        remediation_code_cli: str = "",
        remediation_code_other: str = "",
        resource_tags: dict = None,
        compliance: dict = None,
        repository: str = "",
        issue_labels: list = None,
        finding_url: str = "",
        tenant_info: str = "",
    ) -> bool:
        """
        Send a finding to GitHub as an issue.

        Args:
            check_id: The check ID
            check_title: The check title
            severity: The severity level
            status: The status
            status_extended: Extended status information
            provider: The cloud provider
            region: The region
            resource_uid: The resource UID
            resource_name: The resource name
            risk: Risk description
            recommendation_text: Recommendation text
            recommendation_url: Recommendation URL
            remediation_code_native_iac: Native IaC remediation code
            remediation_code_terraform: Terraform remediation code
            remediation_code_cli: CLI remediation code
            remediation_code_other: Other remediation code
            resource_tags: Resource tags dictionary
            compliance: Compliance frameworks dictionary
            repository: Repository full name (e.g., "owner/repo")
            issue_labels: List of label names to apply
            finding_url: URL to the finding in Prowler
            tenant_info: Tenant information

        Returns:
            True if the issue was created successfully, False otherwise

        Raises:
            GitHubInvalidRepositoryError: If repository is invalid
            GitHubCreateIssueError: If issue creation fails
        """
        try:
            if not repository:
                raise GitHubInvalidParameterError(
                    message="Repository is required",
                    file=os.path.basename(__file__),
                )

            # Validate repository exists
            repositories = self.get_repositories()
            if repository not in repositories:
                raise GitHubInvalidRepositoryError(
                    message=f"Repository '{repository}' not found or not accessible",
                    file=os.path.basename(__file__),
                )

            # Build issue title
            title_parts = ["[Prowler]"]
            if severity:
                title_parts.append(severity.upper())
            if check_id:
                title_parts.append(check_id)
            if resource_uid:
                title_parts.append(resource_uid)

            title = " - ".join(title_parts[1:])
            title = f"{title_parts[0]} {title}"

            # Build issue body
            body = self._build_issue_body(
                check_id=check_id,
                check_title=check_title,
                severity=severity,
                status=status,
                status_extended=status_extended,
                provider=provider,
                region=region,
                resource_uid=resource_uid,
                resource_name=resource_name,
                risk=risk,
                recommendation_text=recommendation_text,
                recommendation_url=recommendation_url,
                remediation_code_native_iac=remediation_code_native_iac,
                remediation_code_terraform=remediation_code_terraform,
                remediation_code_cli=remediation_code_cli,
                remediation_code_other=remediation_code_other,
                resource_tags=resource_tags or {},
                compliance=compliance or {},
                finding_url=finding_url,
                tenant_info=tenant_info,
            )

            # Build payload
            payload = {
                "title": title,
                "body": body,
            }

            if issue_labels:
                payload["labels"] = issue_labels

            # Create issue
            response = requests.post(
                f"{self._api_url}/repos/{repository}/issues",
                headers=self._get_headers(),
                json=payload,
                timeout=10,
            )

            if response.status_code != 201:
                try:
                    response_json = response.json()
                    error_message = response_json.get("message", response.text)
                except (ValueError, requests.exceptions.JSONDecodeError):
                    error_message = response.text

                logger.error(
                    f"Failed to create GitHub issue: {response.status_code} - {error_message}"
                )
                return False

            response_json = response.json()
            issue_url = response_json.get("html_url", "")
            logger.info(f"GitHub issue created successfully: {issue_url}")
            return True

        except GitHubInvalidRepositoryError as e:
            logger.error(f"Invalid repository: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to send finding to GitHub: {str(e)}")
            return False
