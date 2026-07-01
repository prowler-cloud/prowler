from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.marketplace.marketplace_service import (
    Marketplace,
)

marketplace_client = Marketplace(Provider.get_global_provider())
