from prowler.providers.aws.services.neptune.neptune_service import Neptune
from prowler.providers.common.provider import Provider

neptune_client = Neptune(Provider.get_global_provider())
