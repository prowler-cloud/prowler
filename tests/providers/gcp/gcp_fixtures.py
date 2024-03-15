from mock import MagicMock

from prowler.providers.gcp.gcp_provider import GcpProvider

GCP_PROJECT_ID = "123456789012"


def set_mocked_gcp_provider() -> GcpProvider:
    provider = MagicMock()

    return provider
