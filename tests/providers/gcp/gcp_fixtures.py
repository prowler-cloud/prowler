from mock import MagicMock

from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo

GCP_PROJECT_ID = "123456789012"


def set_mocked_gcp_provider(
    project_ids: list[str] = [], profile: str = ""
) -> GcpProvider:
    provider = MagicMock()
    provider.type = "gcp"
    provider.session = None
    provider.project_ids = project_ids
    provider.identity = GCPIdentityInfo(
        profile=profile,
    )

    return provider
