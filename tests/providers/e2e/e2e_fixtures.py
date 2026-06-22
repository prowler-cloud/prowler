import importlib
import sys
from unittest.mock import MagicMock, patch

from prowler.providers.e2e.e2e_provider import E2eProvider
from prowler.providers.e2e.models import E2eIdentityInfo, E2eSession


def run_e2e_check(
    check_module_path: str, client_patch_path: str, client_attr: str, resources: list
):
    """Execute an E2E check with mocked client resources."""
    check_class_name = check_module_path.rsplit(".", 1)[-1]
    client = MagicMock()
    setattr(client, client_attr, resources)

    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_e2e_provider(),
    ):
        if check_module_path in sys.modules:
            module = importlib.reload(sys.modules[check_module_path])
        else:
            module = importlib.import_module(check_module_path)

        with patch(client_patch_path, new=client):
            return getattr(module, check_class_name)().execute()


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
