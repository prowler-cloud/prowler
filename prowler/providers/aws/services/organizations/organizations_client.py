from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from prowler.providers.common.provider import Provider

organizations_client = Organizations(Provider.get_global_provider())
