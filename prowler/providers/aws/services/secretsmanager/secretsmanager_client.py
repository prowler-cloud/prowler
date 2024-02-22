from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from prowler.providers.common.common import get_global_provider

secretsmanager_client = SecretsManager(get_global_provider())
