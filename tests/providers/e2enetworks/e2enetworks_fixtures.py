import importlib
import sys
from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.e2enetworks_provider import E2enetworksProvider
from prowler.providers.e2enetworks.models import (
    E2eNetworksIdentityInfo,
    E2eNetworksSession,
)


def run_e2enetworks_check(
    check_module_path: str, client_patch_path: str, client_attr: str, resources: list
):
    """Execute an E2E check with mocked client resources."""
    check_class_name = check_module_path.rsplit(".", 1)[-1]
    client = MagicMock()
    setattr(client, client_attr, resources)

    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_e2enetworks_provider(),
    ):
        if check_module_path in sys.modules:
            module = importlib.reload(sys.modules[check_module_path])
        else:
            module = importlib.import_module(check_module_path)

        with patch(client_patch_path, new=client):
            return getattr(module, check_class_name)().execute()


def set_mocked_e2enetworks_provider(
    project_id: int = 12345,
    locations: list[str] | None = None,
    audit_config: dict | None = None,
    fixer_config: dict | None = None,
):
    """Create a mocked E2E provider for tests without network calls."""
    provider = MagicMock(spec=E2enetworksProvider)
    provider.type = "e2enetworks"
    provider.audit_config = audit_config or {}
    provider.fixer_config = fixer_config or {}
    provider.identity = E2eNetworksIdentityInfo(
        project_id=project_id,
        locations=locations or ["Delhi"],
    )
    provider.session = E2eNetworksSession(
        api_key="test-api-key",
        auth_token="test-auth-token",
        project_id=project_id,
        locations=locations or ["Delhi"],
        http_session=MagicMock(),
    )
    return provider
