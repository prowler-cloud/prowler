from prowler.providers.aws.services.securityhub.securityhub_service import SecurityHub
from prowler.providers.common.provider import Provider

securityhub_client = SecurityHub(Provider.get_global_provider())
