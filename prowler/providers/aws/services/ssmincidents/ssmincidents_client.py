from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    SSMIncidents,
)
from prowler.providers.common.common import get_global_provider

ssmincidents_client = SSMIncidents(get_global_provider())
