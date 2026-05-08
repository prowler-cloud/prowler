"""Reusable Lovable test fixtures."""

from unittest.mock import MagicMock

from prowler.providers.lovable.models import (
    LovableIdentityInfo,
    LovableSession,
    LovableWorkspaceInfo,
)

API_TOKEN = "lovable_test_token_xxxxxxxxxxxxxxxxxxxxxx"
WORKSPACE_ID = "ws_test_workspace"
WORKSPACE_NAME = "Test Workspace"
WORKSPACE_SLUG = "test-workspace"
USER_ID = "user_test_id"
USER_EMAIL = "test@example.com"
USERNAME = "testuser"


def make_session(workspace_id: str = WORKSPACE_ID) -> LovableSession:
    return LovableSession(
        api_token=API_TOKEN,
        workspace_id=workspace_id,
        http_session=MagicMock(),
    )


def make_identity() -> LovableIdentityInfo:
    workspace = LovableWorkspaceInfo(
        id=WORKSPACE_ID,
        name=WORKSPACE_NAME,
        slug=WORKSPACE_SLUG,
        plan="pro",
    )
    return LovableIdentityInfo(
        user_id=USER_ID,
        username=USERNAME,
        email=USER_EMAIL,
        workspace=workspace,
        workspaces=[workspace],
    )


def make_provider() -> MagicMock:
    """Build a stub provider sufficient for service constructors."""
    provider = MagicMock()
    provider.session = make_session()
    provider.identity = make_identity()
    provider.audit_config = {"max_retries": 0}
    provider.fixer_config = {}
    provider.filter_projects = None
    provider.published_app_urls = []
    provider.supabase_access_token = None
    return provider


def set_mocked_lovable_provider() -> MagicMock:
    """Alias used by check tests, mirroring the Vercel test pattern."""
    return make_provider()
