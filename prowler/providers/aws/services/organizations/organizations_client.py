from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from prowler.providers.common.common import get_global_provider

organizations_client = Organizations(get_global_provider())
