from prowler.providers.aws.services.securityhub.securityhub_service import SecurityHub
from prowler.providers.common.common import get_global_provider

securityhub_client = SecurityHub(get_global_provider())
