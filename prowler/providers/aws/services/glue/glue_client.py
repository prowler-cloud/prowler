from prowler.providers.aws.services.glue.glue_service import Glue
from prowler.providers.common.common import get_global_provider

glue_client = Glue(get_global_provider())
