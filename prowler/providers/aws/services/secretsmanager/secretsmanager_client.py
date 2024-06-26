from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from prowler.providers.common.provider import Provider

secretsmanager_client = SecretsManager(Provider.get_global_provider())
