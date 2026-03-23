from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class Project(VercelService):
    """Retrieve Vercel projects with security-relevant settings and environment variables."""

    def __init__(self, provider):
        super().__init__("Project", provider)
        self.projects: dict[str, VercelProject] = {}
        self._list_projects()
        self.__threading_call__(self._fetch_env_vars, list(self.projects.values()))

    def _list_projects(self):
        """List all projects, optionally filtered by --project argument."""
        try:
            raw_projects = self._paginate("/v9/projects", "projects")

            filter_projects = self.provider.filter_projects
            seen_ids: set[str] = set()

            for proj in raw_projects:
                project_id = proj.get("id")
                if not project_id or project_id in seen_ids:
                    continue
                seen_ids.add(project_id)

                project_name = proj.get("name", "")

                # Apply project filter if specified
                if filter_projects and (
                    project_id not in filter_projects
                    and project_name not in filter_projects
                ):
                    continue

                # Parse deployment protection
                dp = None
                dp_raw = proj.get("deploymentProtection", {}) or {}

                preview_dp = dp_raw.get("deploymentType", "none")
                if preview_dp and preview_dp != "none":
                    dp = DeploymentProtectionConfig(level=preview_dp)

                prod_dp = None
                prod_raw = dp_raw.get("prod", {}) or {}
                prod_level = prod_raw.get("deploymentType", "none")
                if prod_level and prod_level != "none":
                    prod_dp = DeploymentProtectionConfig(level=prod_level)

                # Parse password protection
                pwd_protection = proj.get("passwordProtection")

                self.projects[project_id] = VercelProject(
                    id=project_id,
                    name=project_name,
                    team_id=proj.get("accountId") or self.provider.session.team_id,
                    framework=proj.get("framework"),
                    node_version=proj.get("nodeVersion"),
                    auto_expose_system_envs=proj.get("autoExposeSystemEnvs", False),
                    directory_listing=proj.get("directoryListing", False),
                    skew_protection=(
                        proj.get("skewProtection") == "enabled"
                        if isinstance(proj.get("skewProtection"), str)
                        else bool(proj.get("skewProtection", False))
                    ),
                    deployment_protection=dp,
                    production_deployment_protection=prod_dp,
                    password_protection=pwd_protection,
                    git_fork_protection=proj.get("gitForkProtection", True),
                    git_repository=proj.get("link"),
                    secure_compute=proj.get("secureCompute"),
                )

            logger.info(f"Project - Found {len(self.projects)} project(s)")

        except Exception as error:
            logger.error(
                f"Project - Error listing projects: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _fetch_env_vars(self, project: "VercelProject"):
        """Fetch environment variables for a single project."""
        try:
            env_data = self._paginate(f"/v9/projects/{project.id}/env", "envs")

            env_vars = []
            for env in env_data:
                env_vars.append(
                    VercelEnvironmentVariable(
                        id=env.get("id", ""),
                        key=env.get("key", ""),
                        type=env.get("type", "plain"),
                        target=env.get("target", []),
                        project_id=project.id,
                        project_name=project.name,
                        git_branch=env.get("gitBranch"),
                        created_at=(
                            datetime.fromtimestamp(
                                env["createdAt"] / 1000, tz=timezone.utc
                            )
                            if env.get("createdAt")
                            else None
                        ),
                    )
                )

            project.environment_variables = env_vars
            logger.debug(
                f"Project - Fetched {len(env_vars)} env vars for project {project.name}"
            )

        except Exception as error:
            logger.error(
                f"Project - Error fetching env vars for {project.name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class DeploymentProtectionConfig(BaseModel):
    """Per-environment deployment protection settings."""

    level: str = "none"  # "standard" | "all" | "none"
    method: Optional[str] = None


class VercelEnvironmentVariable(BaseModel):
    """Vercel project environment variable."""

    id: str
    key: str
    type: str = "plain"  # "encrypted" | "plain" | "secret" | "system"
    target: list[str] = Field(default_factory=list)
    project_id: str = ""
    project_name: Optional[str] = None
    git_branch: Optional[str] = None
    created_at: Optional[datetime] = None


class VercelProject(BaseModel):
    """Vercel project representation used across checks."""

    id: str
    name: str
    team_id: Optional[str] = None
    framework: Optional[str] = None
    node_version: Optional[str] = None
    auto_expose_system_envs: bool = False
    directory_listing: bool = False
    skew_protection: bool = False
    deployment_protection: Optional[DeploymentProtectionConfig] = None
    production_deployment_protection: Optional[DeploymentProtectionConfig] = None
    password_protection: Optional[dict] = None
    git_fork_protection: bool = True
    git_repository: Optional[dict] = None
    secure_compute: Optional[dict] = None
    environment_variables: list[VercelEnvironmentVariable] = Field(default_factory=list)
