from prowler.providers.aws.services.athena.athena_service import Athena
from prowler.providers.common.common import get_global_provider

athena_client = Athena(get_global_provider())
