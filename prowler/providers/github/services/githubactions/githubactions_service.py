import io
import json
import shutil
import subprocess
import tempfile
from fnmatch import fnmatch
from os.path import basename
from typing import Optional

from dulwich import porcelain
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.lib.service.service import GithubService


class GithubActions(GithubService):
    def __init__(self, provider: GithubProvider):
        super().__init__(__class__.__name__, provider)

        self.findings: dict[int, list[GithubActionsWorkflowFinding]] = {}
        self.scan_enabled = False

        if not getattr(provider, "github_actions_enabled", True):
            logger.info(
                "GitHub Actions scanning is disabled via --no-github-actions flag."
            )
            return

        if not shutil.which("zizmor"):
            logger.warning(
                "zizmor binary not found. Skipping GitHub Actions workflow security scanning. "
                "Install zizmor from https://github.com/woodruffw/zizmor"
            )
            return

        self.scan_enabled = True

        self._scan_repositories(provider)

    def _scan_repositories(self, provider: GithubProvider):
        from prowler.providers.github.services.repository.repository_client import (
            repository_client,
        )

        exclude_workflows = getattr(provider, "exclude_workflows", []) or []

        for repo_id, repo in repository_client.repositories.items():
            temp_dir = None
            try:
                temp_dir = self._clone_repository(
                    f"https://github.com/{repo.full_name}",
                    provider.session.token,
                )
                if not temp_dir:
                    continue

                raw_findings = self._run_zizmor(temp_dir)

                repo_findings = []
                for finding in raw_findings:
                    for location in finding.get("locations", []):
                        workflow_file = self._extract_workflow_file_from_location(
                            location
                        )
                        if not workflow_file:
                            continue
                        if workflow_file.startswith(temp_dir):
                            workflow_file = workflow_file[len(temp_dir) :].lstrip("/")
                        if self._should_exclude_workflow(
                            workflow_file, exclude_workflows
                        ):
                            continue

                        parsed = self._parse_finding(
                            finding, workflow_file, location, repo
                        )
                        if parsed:
                            repo_findings.append(parsed)

                self.findings[repo_id] = repo_findings

            except Exception as error:
                logger.error(
                    f"Error scanning repository {repo.full_name}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            finally:
                if temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)

    def _clone_repository(
        self, repository_url: str, token: str = None
    ) -> Optional[str]:
        try:
            auth_url = repository_url
            if token:
                auth_url = repository_url.replace(
                    "https://github.com/",
                    f"https://{token}@github.com/",
                )

            temp_dir = tempfile.mkdtemp()
            logger.info(f"Cloning repository {repository_url} into {temp_dir}...")
            porcelain.clone(auth_url, temp_dir, depth=1, errstream=io.BytesIO())
            return temp_dir
        except Exception as error:
            error_msg = str(error)
            if token:
                error_msg = error_msg.replace(token, "***")
            logger.error(
                f"Failed to clone {repository_url}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error_msg}"
            )
            return None

    def _run_zizmor(self, directory: str) -> list[dict]:
        try:
            process = subprocess.run(
                ["zizmor", directory, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=1800,
            )

            if process.stderr:
                for line in process.stderr.strip().split("\n"):
                    if line.strip():
                        logger.debug(f"zizmor: {line}")

            if not process.stdout:
                return []

            output = json.loads(process.stdout)
            if not output or (isinstance(output, list) and len(output) == 0):
                return []

            return output

        except json.JSONDecodeError as error:
            logger.warning(f"Failed to parse zizmor output as JSON: {error}")
            return []
        except Exception as error:
            logger.error(
                f"Error running zizmor: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    @staticmethod
    def _should_exclude_workflow(
        workflow_file: str, exclude_patterns: list[str]
    ) -> bool:
        if not exclude_patterns:
            return False

        filename = basename(workflow_file)

        for pattern in exclude_patterns:
            if fnmatch(workflow_file, pattern):
                logger.debug(
                    f"Excluding workflow {workflow_file} (matches full path pattern: {pattern})"
                )
                return True
            if fnmatch(filename, pattern):
                logger.debug(
                    f"Excluding workflow {workflow_file} (matches filename pattern: {pattern})"
                )
                return True

        return False

    @staticmethod
    def _extract_workflow_file_from_location(location: dict) -> Optional[str]:
        try:
            symbolic = location.get("symbolic", {})
            if "key" in symbolic:
                key = symbolic["key"]
                if isinstance(key, dict) and "Local" in key:
                    local = key["Local"]
                    if isinstance(local, dict) and "given_path" in local:
                        return local["given_path"]

            logger.debug(f"Could not extract workflow file from location: {location}")
            return None
        except Exception as error:
            logger.error(
                f"Error extracting workflow file from location: "
                f"{error.__class__.__name__} - {error}"
            )
            return None

    @staticmethod
    def _parse_finding(
        finding: dict, workflow_file: str, location: dict, repo
    ) -> Optional["GithubActionsWorkflowFinding"]:
        try:
            concrete_location = location.get("concrete", {}).get("location", {})
            start = concrete_location.get("start_point", {})
            end = concrete_location.get("end_point", {})

            if start and end:
                if start.get("row") == end.get("row"):
                    line_range = f"line {start.get('row', 'unknown')}"
                else:
                    line_range = f"lines {start.get('row', 'unknown')}-{end.get('row', 'unknown')}"
            else:
                line_range = "location unknown"

            determinations = finding.get("determinations", {})
            severity = determinations.get("severity", "Unknown").lower()
            confidence = determinations.get("confidence", "Unknown")

            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "informational",
                "unknown": "medium",
            }

            default_branch = getattr(
                getattr(repo, "default_branch", None), "name", "main"
            )
            workflow_url = f"https://github.com/{repo.full_name}/blob/{default_branch}/{workflow_file}"

            ident = finding.get("ident", "unknown")

            return GithubActionsWorkflowFinding(
                repo_id=repo.id,
                repo_name=repo.name,
                repo_full_name=repo.full_name,
                repo_owner=repo.owner,
                workflow_file=workflow_file,
                workflow_url=workflow_url,
                line_range=line_range,
                finding_id=f"githubactions_{ident.replace('-', '_')}",
                ident=ident,
                description=finding.get(
                    "desc", "Security issue detected in GitHub Actions workflow"
                ),
                severity=severity_map.get(severity, "medium"),
                confidence=confidence,
                annotation=location.get("symbolic", {}).get(
                    "annotation", "No details available"
                ),
                url=finding.get("url", "https://docs.zizmor.sh/"),
            )
        except Exception as error:
            logger.error(
                f"Error parsing zizmor finding: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


class GithubActionsWorkflowFinding(BaseModel):
    repo_id: int
    repo_name: str
    repo_full_name: str
    repo_owner: str
    workflow_file: str
    workflow_url: str
    line_range: str
    finding_id: str
    ident: str
    description: str
    severity: str
    confidence: str
    annotation: str
    url: str
