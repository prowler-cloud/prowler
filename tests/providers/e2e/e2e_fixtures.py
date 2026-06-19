from unittest.mock import MagicMock

from prowler.providers.e2e.e2e_provider import E2eProvider
from prowler.providers.e2e.models import E2eIdentityInfo, E2eSession


def set_mocked_e2e_provider(
    project_id: int = 12345,
    locations: list[str] | None = None,
    audit_config: dict | None = None,
    fixer_config: dict | None = None,
):
    """Create a mocked E2E provider for tests without network calls."""
    provider = MagicMock(spec=E2eProvider)
    provider.type = "e2e"
    provider.audit_config = audit_config or {}
    provider.fixer_config = fixer_config or {}
    provider.identity = E2eIdentityInfo(
        project_id=project_id,
        locations=locations or ["Delhi"],
    )
    provider.session = E2eSession(
        api_key="test-api-key",
        auth_token="test-auth-token",
        project_id=project_id,
        locations=locations or ["Delhi"],
        http_session=MagicMock(),
    )
    return provider
