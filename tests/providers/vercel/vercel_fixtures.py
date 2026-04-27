from unittest.mock import MagicMock

from prowler.providers.vercel.models import (
    VercelIdentityInfo,
    VercelSession,
    VercelTeamInfo,
)

# Vercel Identity
TEAM_ID = "team_test123"
TEAM_NAME = "Test Team"
TEAM_SLUG = "test-team"
USER_ID = "user_test456"
USERNAME = "testuser"
USER_EMAIL = "test@example.com"

# Vercel Credentials
API_TOKEN = "test-vercel-api-token"

# Project Constants
PROJECT_ID = "prj_test789"
PROJECT_NAME = "my-test-project"

# Domain Constants
DOMAIN_NAME = "example.com"

# Deployment Constants
DEPLOYMENT_ID = "dpl_test012"


def set_mocked_vercel_provider(
    api_token: str = API_TOKEN,
    team_id: str = TEAM_ID,
    identity: VercelIdentityInfo = None,
    audit_config: dict = None,
    billing_plan: str = None,
):
    """Create a mocked VercelProvider for testing."""
    provider = MagicMock()
    provider.type = "vercel"
    provider.session = VercelSession(
        token=api_token,
        team_id=team_id,
        http_session=MagicMock(),
    )
    provider.identity = identity or VercelIdentityInfo(
        user_id=USER_ID,
        username=USERNAME,
        email=USER_EMAIL,
        billing_plan=billing_plan,
        team=VercelTeamInfo(
            id=TEAM_ID,
            name=TEAM_NAME,
            slug=TEAM_SLUG,
            billing_plan=billing_plan,
        ),
    )
    provider.audit_config = audit_config or {"max_retries": 3}
    provider.fixer_config = {}
    provider.filter_projects = None

    return provider
