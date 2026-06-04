from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.groups.groups_service import (
    Groups,
)

groups_client = Groups(Provider.get_global_provider())
