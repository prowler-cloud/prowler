from prowler.providers.common.provider import Provider
from prowler.providers.e2e.services.securitygroup.securitygroup_service import (
    SecurityGroups,
)

securitygroup_client = SecurityGroups(Provider.get_global_provider())
