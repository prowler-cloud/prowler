from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.secretmanager.secretmanager_service import (
    SecretManager,
)

secretmanager_client = SecretManager(Provider.get_global_provider())
