from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.groups.groups_service import (
    GroupsForBusiness,
)

groups_client = GroupsForBusiness(Provider.get_global_provider())
