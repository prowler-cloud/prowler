from prowler.providers.aws.services.rolesanywhere.rolesanywhere_service import (
    RolesAnywhere,
)
from prowler.providers.common.provider import Provider

rolesanywhere_client = RolesAnywhere(Provider.get_global_provider())
