from mock import MagicMock

from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo

GCP_PROJECT_ID = "123456789012"


def set_mocked_gcp_provider(
    project_ids: list[str] = [], default_project_id: str = "", profile: str = ""
) -> GcpProvider:
    provider = MagicMock()
    provider.session = None
    provider.project_ids = project_ids
    provider.identity = GCPIdentityInfo(
        profile=profile,
        default_project_id=default_project_id,
    )

    return provider
