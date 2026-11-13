from typing import Optional

from pydantic import Field

from prowler.providers.supabase.lib.service.service import (
    SupabaseProjectScope,
    SupabaseService,
)


class Projects(SupabaseService):
    """Retrieve Supabase projects with their platform-level security settings."""

    def __init__(self, provider):
        super().__init__("Projects", provider)
        self.projects: dict[str, SupabaseProject] = {}
        for scope in self._list_projects():
            self.projects[scope.project_ref] = SupabaseProject(**scope.model_dump())
        self._threading_call(self._fetch_settings, list(self.projects.values()))

    def _fetch_settings(self, project: "SupabaseProject") -> None:
        """Collect SSL, network, Data API, backup and API key settings for a project."""
        ref = project.project_ref

        ssl = self._get_optional(
            f"/v1/projects/{ref}/ssl-enforcement", "SSL enforcement"
        )
        if ssl is not None:
            project.ssl_enforced = bool(
                (ssl.get("currentConfig") or {}).get("database")
            )

        network = self._get_optional(
            f"/v1/projects/{ref}/network-restrictions", "Network restrictions"
        )
        if network is not None:
            config = network.get("config") or {}
            project.network_restrictions_entitled = (
                network.get("entitlement") == "allowed"
            )
            project.allowed_cidrs = list(config.get("dbAllowedCidrs") or [])
            project.allowed_cidrs_v6 = list(config.get("dbAllowedCidrsV6") or [])

        postgrest = self._get_optional(
            f"/v1/projects/{ref}/postgrest", "PostgREST config"
        )
        if postgrest is not None:
            project.postgrest_max_rows = postgrest.get("max_rows")
            project.postgrest_db_schema = postgrest.get("db_schema")

        backups = self._get_optional(f"/v1/projects/{ref}/database/backups", "Backups")
        if backups is not None:
            project.pitr_enabled = bool(backups.get("pitr_enabled"))

        legacy = self._get_optional(
            f"/v1/projects/{ref}/api-keys/legacy", "Legacy API keys"
        )
        if legacy is not None:
            project.legacy_api_keys_enabled = bool(legacy.get("enabled"))


class SupabaseProject(SupabaseProjectScope):
    """Security-relevant Supabase project settings.

    Attributes left as ``None`` could not be read from the Management API and
    are skipped by the checks instead of being reported as failures.
    """

    ssl_enforced: Optional[bool] = None
    network_restrictions_entitled: Optional[bool] = None
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_cidrs_v6: list[str] = Field(default_factory=list)
    postgrest_max_rows: Optional[int] = None
    postgrest_db_schema: Optional[str] = None
    pitr_enabled: Optional[bool] = None
    legacy_api_keys_enabled: Optional[bool] = None

    @property
    def allowed_cidrs_restricted(self) -> bool:
        """True when at least one range is allowed and none of them is the whole internet."""
        ranges = [*self.allowed_cidrs, *self.allowed_cidrs_v6]
        return bool(ranges) and not any(
            cidr.strip() in ("0.0.0.0/0", "::/0") for cidr in ranges
        )
