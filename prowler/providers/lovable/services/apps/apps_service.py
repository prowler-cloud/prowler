"""Apps service.

A Lovable "app" is what the platform calls a project: an AI-generated web
app that is composed of a frontend bundle, optional Supabase backend, and an
optional published URL. This service hydrates the app inventory used by every
check in the provider.
"""

from typing import Optional

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.lovable.lib.service.service import LovableService


class LovableApp(BaseModel):
    """A single Lovable project / published app."""

    id: str
    name: str = ""
    slug: str = ""
    workspace_id: str = ""
    visibility: str = "unknown"  # public | workspace | private | unknown
    is_published: bool = False
    published_url: Optional[str] = None

    # Pre-publication security review
    security_review_run: bool = False
    security_review_findings: int = 0
    security_review_last_run: Optional[str] = None

    # Authentication & user management
    auth_enabled: bool = False
    captcha_enabled: bool = False
    password_min_length: int = 0
    password_requires_uppercase: bool = False
    password_requires_lowercase: bool = False
    password_requires_number: bool = False
    password_requires_symbol: bool = False
    auth_rate_limit_enabled: bool = False

    # Supabase backing
    has_supabase_backing: bool = False
    supabase_project_ref: Optional[str] = None
    rls_enabled_on_all_tables: bool = True
    tables_without_rls: list[str] = Field(default_factory=list)

    # Edge Functions
    edge_functions: list[str] = Field(default_factory=list)
    edge_functions_with_auth: list[str] = Field(default_factory=list)

    # Storage
    storage_buckets_public: list[str] = Field(default_factory=list)
    storage_buckets_private: list[str] = Field(default_factory=list)

    tags: dict = Field(default_factory=dict)


class Apps(LovableService):
    """Inventory of Lovable apps (projects)."""

    def __init__(self, provider):
        super().__init__("Apps", provider)
        self.apps: dict[str, LovableApp] = {}
        self._fetch_apps()

    def _fetch_apps(self) -> None:
        try:
            payload = self._paginate("/projects", key="projects")
            workspace_id = self._workspace_id or (
                self.provider.identity.workspace.id
                if self.provider.identity.workspace
                else ""
            )

            project_filter = self.provider.filter_projects

            for raw in payload:
                project_id = raw.get("id")
                if not project_id:
                    continue
                if project_filter and not (
                    project_id in project_filter
                    or raw.get("slug") in project_filter
                    or raw.get("name") in project_filter
                ):
                    continue

                self.apps[project_id] = self._build_app(raw, workspace_id)

            # Allow operator-supplied URLs even when the API has no apps for us.
            for url in self.provider.published_app_urls:
                synthetic_id = f"manual::{url}"
                self.apps[synthetic_id] = LovableApp(
                    id=synthetic_id,
                    name=url,
                    slug=url,
                    workspace_id=workspace_id,
                    visibility="public",
                    is_published=True,
                    published_url=url,
                )

            logger.info(f"Apps - Loaded {len(self.apps)} Lovable app(s).")
        except Exception as error:
            logger.error(
                f"Apps - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _build_app(self, raw: dict, workspace_id: str) -> LovableApp:
        """Map a raw Lovable Cloud project payload to LovableApp."""
        raw.get("security") or {}
        auth = raw.get("auth") or {}
        password = (auth.get("password_policy") or {}) if isinstance(auth, dict) else {}
        supabase = raw.get("supabase") or {}
        review = raw.get("security_review") or {}

        return LovableApp(
            id=raw.get("id", ""),
            name=raw.get("name") or raw.get("slug") or raw.get("id", ""),
            slug=raw.get("slug", ""),
            workspace_id=raw.get("workspace_id") or workspace_id,
            visibility=(raw.get("visibility") or "unknown").lower(),
            is_published=bool(raw.get("is_published") or raw.get("published_url")),
            published_url=raw.get("published_url"),
            security_review_run=bool(review.get("last_run_at")),
            security_review_findings=int(review.get("open_findings", 0) or 0),
            security_review_last_run=review.get("last_run_at"),
            auth_enabled=bool(auth.get("enabled")),
            captcha_enabled=bool(auth.get("captcha_enabled")),
            password_min_length=int(password.get("min_length", 0) or 0),
            password_requires_uppercase=bool(password.get("requires_uppercase")),
            password_requires_lowercase=bool(password.get("requires_lowercase")),
            password_requires_number=bool(password.get("requires_number")),
            password_requires_symbol=bool(password.get("requires_symbol")),
            auth_rate_limit_enabled=bool(auth.get("rate_limit_enabled")),
            has_supabase_backing=bool(supabase.get("project_ref")),
            supabase_project_ref=supabase.get("project_ref"),
            rls_enabled_on_all_tables=bool(supabase.get("rls_all_tables", True)),
            tables_without_rls=list(supabase.get("tables_without_rls", []) or []),
            edge_functions=list(supabase.get("edge_functions", []) or []),
            edge_functions_with_auth=list(
                supabase.get("edge_functions_with_auth", []) or []
            ),
            storage_buckets_public=list(supabase.get("buckets_public", []) or []),
            storage_buckets_private=list(supabase.get("buckets_private", []) or []),
            tags=raw.get("tags") or {},
        )
