from pydantic import BaseModel, Field

from prowler.providers.supabase.lib.service.service import (
    SupabaseProjectScope,
    SupabaseService,
)

# Lints that describe the advisor itself rather than the database schema
NON_SCHEMA_LINTS = {"project_not_active", "advisor_check_unavailable"}


class Database(SupabaseService):
    """Retrieve the Postgres security posture of every project.

    The Supabase security advisor runs the same lints as the dashboard
    (``splinter``) and exposes them through the Management API, so no SQL
    is executed against customer databases.
    """

    def __init__(self, provider):
        super().__init__("Database", provider)
        self.databases: dict[str, SupabaseDatabase] = {}
        self._threading_call(self._fetch_lints, self._list_projects())

    def _fetch_lints(self, scope: SupabaseProjectScope) -> None:
        """Store the security lints of a project; unavailable projects are skipped."""
        raw = self._get_optional(
            f"/v1/projects/{scope.project_ref}/advisors/security", "Security advisor"
        )
        if raw is None:
            return
        lints = []
        advisor_available = True
        for item in raw.get("lints") or []:
            name = item.get("name", "")
            if name in NON_SCHEMA_LINTS:
                advisor_available = False
                continue
            metadata = item.get("metadata") or {}
            lints.append(
                SupabaseDatabaseLint(
                    name=name,
                    title=item.get("title", ""),
                    level=item.get("level", ""),
                    schema_name=metadata.get("schema") or "",
                    object_name=metadata.get("name") or metadata.get("entity") or "",
                    object_type=metadata.get("type") or "",
                    detail=item.get("detail") or "",
                    remediation=item.get("remediation") or "",
                )
            )
        self.databases[scope.project_ref] = SupabaseDatabase(
            **scope.model_dump(), advisor_available=advisor_available, lints=lints
        )


class SupabaseDatabaseLint(BaseModel):
    """One security advisor finding on a database object."""

    name: str
    title: str = ""
    level: str = ""
    schema_name: str = ""
    object_name: str = ""
    object_type: str = ""
    detail: str = ""
    remediation: str = ""

    @property
    def qualified_name(self) -> str:
        """``schema.object`` when both are known, otherwise whichever exists."""
        return ".".join(part for part in (self.schema_name, self.object_name) if part)


class SupabaseDatabase(SupabaseProjectScope):
    """Postgres database of a project with its security advisor lints."""

    advisor_available: bool = True
    lints: list[SupabaseDatabaseLint] = Field(default_factory=list)

    def lints_named(self, *names: str) -> list[SupabaseDatabaseLint]:
        """Return the lints matching any of the given advisor names."""
        return [lint for lint in self.lints if lint.name in names]


class SupabaseDatabaseObject(SupabaseProjectScope):
    """Database object a lint points at, used as the failing finding resource."""

    lint: SupabaseDatabaseLint
