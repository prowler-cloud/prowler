from uuid import uuid4

from mock import MagicMock

from prowler.providers.stackit.models import StackITIdentityInfo
from prowler.providers.stackit.stackit_provider import StackitProvider

# StackIT Test Constants
STACKIT_PROJECT_ID = str(uuid4())
STACKIT_SERVICE_ACCOUNT_KEY_PATH = "/tmp/stackit-sa-key.json"
STACKIT_PROJECT_NAME = "Test Project"


def set_mocked_stackit_provider(
    service_account_key_path: str = STACKIT_SERVICE_ACCOUNT_KEY_PATH,
    project_id: str = STACKIT_PROJECT_ID,
    identity: StackITIdentityInfo = None,
    audit_config: dict = None,
    fixer_config: dict = None,
    scan_unused_services: bool = False,
) -> StackitProvider:
    """
    Create a mocked StackIT provider for testing.

    Args:
        service_account_key_path: Path to the service account key file
            (default: ``STACKIT_SERVICE_ACCOUNT_KEY_PATH`` constant)
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
        )

    provider = MagicMock()
    provider.type = "stackit"
    provider.identity = identity
    provider.session = {
        "project_id": project_id,
        "service_account_key_path": service_account_key_path,
    }
    provider.audit_config = audit_config if audit_config else {}
    provider.fixer_config = fixer_config if fixer_config else {}
    provider.scan_unused_services = scan_unused_services
    provider.auth_method = "service_account_key"

    return provider
