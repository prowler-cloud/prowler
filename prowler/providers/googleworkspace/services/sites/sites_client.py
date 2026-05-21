from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.sites.sites_service import (
    Sites,
)

sites_client = Sites(Provider.get_global_provider())
