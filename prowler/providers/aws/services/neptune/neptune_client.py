from prowler.providers.aws.services.neptune.neptune_service import Neptune
from prowler.providers.common.common import get_global_provider

neptune_client = Neptune(get_global_provider())
