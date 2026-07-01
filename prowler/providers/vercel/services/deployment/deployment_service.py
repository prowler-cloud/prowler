from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class Deployment(VercelService):
    """Retrieve recent Vercel deployments."""

    def __init__(self, provider):
        super().__init__("Deployment", provider)
        self.deployments: dict[str, VercelDeployment] = {}
        self._list_deployments()

    def _list_deployments(self):
        """List recent deployments across all projects."""
        try:
            params = {"limit": 100}
            # Fetch only recent deployments (first page is sufficient for security checks)
            raw_deployments = self._paginate("/v6/deployments", "deployments", params)

            seen_ids: set[str] = set()
            filter_projects = self.provider.filter_projects

            for dep in raw_deployments:
                dep_id = dep.get("uid", dep.get("id", ""))
                if not dep_id or dep_id in seen_ids:
                    continue
                seen_ids.add(dep_id)

                project_id = dep.get("projectId", "")

                # Apply project filter if specified
                if filter_projects and project_id not in filter_projects:
                    project_name = dep.get("name", "")
                    if project_name not in filter_projects:
                        continue

                created_at = None
                if dep.get("createdAt"):
                    created_at = datetime.fromtimestamp(
                        dep["createdAt"] / 1000, tz=timezone.utc
                    )

                ready_at = None
                if dep.get("ready"):
                    ready_at = datetime.fromtimestamp(
                        dep["ready"] / 1000, tz=timezone.utc
                    )

                git_source = None
                meta = dep.get("meta", {}) or {}
                if meta.get("githubCommitSha") or meta.get("gitlabCommitSha"):
                    git_source = {
                        "commit_sha": meta.get("githubCommitSha")
                        or meta.get("gitlabCommitSha"),
                        "branch": meta.get("githubCommitRef")
                        or meta.get("gitlabCommitRef"),
                        "repo": meta.get("githubRepo") or meta.get("gitlabRepo"),
                    }

                self.deployments[dep_id] = VercelDeployment(
                    id=dep_id,
                    name=dep.get("name", ""),
                    url=dep.get("url", ""),
                    state=dep.get("state", dep.get("readyState", "")),
                    target=dep.get("target"),
                    created_at=created_at,
                    ready_at=ready_at,
                    project_id=project_id,
                    project_name=dep.get("name", ""),
                    team_id=dep.get("teamId") or self.provider.session.team_id,
                    git_source=git_source,
                    deployment_protection=dep.get("deploymentProtection"),
                )

            logger.info(f"Deployment - Found {len(self.deployments)} deployment(s)")

        except Exception as error:
            logger.error(
                f"Deployment - Error listing deployments: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VercelDeployment(BaseModel):
    """Vercel deployment representation."""

    id: str
    name: str
    url: str = ""
    state: str = ""
    target: Optional[str] = None  # "production" | "preview"
    created_at: Optional[datetime] = None
    ready_at: Optional[datetime] = None
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    team_id: Optional[str] = None
    git_source: Optional[dict] = None
    deployment_protection: Optional[dict] = None
