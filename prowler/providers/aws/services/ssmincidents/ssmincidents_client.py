from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    SSMIncidents,
)
from prowler.providers.common.provider import Provider

ssmincidents_client = SSMIncidents(Provider.get_global_provider())
