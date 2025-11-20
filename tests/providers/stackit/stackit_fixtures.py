from uuid import uuid4

from mock import MagicMock

from prowler.providers.stackit.models import StackITIdentityInfo
from prowler.providers.stackit.stackit_provider import StackitProvider

# StackIT Test Constants
STACKIT_PROJECT_ID = str(uuid4())
STACKIT_API_TOKEN = "test-api-token-" + str(uuid4())
STACKIT_PROJECT_NAME = "Test Project"
STACKIT_ACCOUNT_ID = str(uuid4())


def set_mocked_stackit_provider(
    api_token: str = STACKIT_API_TOKEN,
    project_id: str = STACKIT_PROJECT_ID,
    identity: StackITIdentityInfo = None,
    audit_config: dict = None,
    fixer_config: dict = None,
) -> StackitProvider:
    """
    Create a mocked StackIT provider for testing.

    Args:
        api_token: The API token to use (default: STACKIT_API_TOKEN)
        project_id: The project ID to use (default: STACKIT_PROJECT_ID)
        identity: Custom identity info (default: creates new StackITIdentityInfo)
        audit_config: Audit configuration dict (default: None)
        fixer_config: Fixer configuration dict (default: None)

    Returns:
        MagicMock: A mocked StackitProvider instance
    """
    if identity is None:
        identity = StackITIdentityInfo(
            project_id=project_id,
            project_name=STACKIT_PROJECT_NAME,
            account_id=STACKIT_ACCOUNT_ID,
        )

    provider = MagicMock()
    provider.type = "stackit"
    provider.identity = identity
    provider.session = {
        "api_token": api_token,
        "project_id": project_id,
    }
    provider.audit_config = audit_config if audit_config else {}
    provider.fixer_config = fixer_config if fixer_config else {}

    return provider
